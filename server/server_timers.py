"""server_timers.py - modulo de TEMPO do servidor-lab (standalone, offline).

Relogio real int(time.time()), injetavel (now=callable) para testes.

Partes:
  1. Queue / QueueManager  - fila de obras/pesquisas com end_time real (notify_queue_update)
  2. offline_gain          - progresso offline (notify_offline_info), calibrado no fixture
  3. SurvivorWork / Station - trabalho de sobrevivente + coleta (work_endtime, remaining_mti)
  4. qtime_id / schedule_update - agenda (qtime_seqment) por hora do dia
  5. cfg helpers           - build_time(bid, lv), tech_time(tid, lv) lendo lua-logic/cfg
"""
import json
import os
import time

CFG_DIR = os.environ.get(
    "KS_CFG_DIR", "C:/Users/prs/work/lua-logic/cfg")


def real_now():
    return int(time.time())


# --------------------------------------------------------------------- cfg
_cache = {}


def _load(name, cfg_dir=None):
    p = os.path.join(cfg_dir or CFG_DIR, name + ".json")
    if p not in _cache:
        with open(p, encoding="utf-8") as f:
            _cache[p] = json.load(f)
    return _cache[p]


def build_time(bid, level, cfg_dir=None):
    """Segundos para chegar ao nivel `level` (blv) da construcao bid (301..414).
    costTime fica na linha cujo blv == level (a chave da tabela NAO e o nivel
    em todas: build301 chave=blv+1, build302 chave=blv)."""
    for row in _load("build%d" % bid, cfg_dir).values():
        if row.get("blv") == level:
            return int(row.get("costTime", 0))
    raise KeyError((bid, level))


def tech_time(tid, level, cfg_dir=None):
    """technology_detail_config: chave = str(tid)+str(nivel) (ex.: 1001,2 -> "10012")."""
    row = _load("technology_detail_config", cfg_dir)[str(tid) + str(level)]
    return int(row["cost_time"])


def soldier_train_time(sid, cfg_dir=None):
    """soldiers.json: training_time por soldado (unidade: segundos por soldado; 12 no T1)."""
    return _load("soldiers", cfg_dir)[str(sid)].get("training_time")


def sysconf(cfg_dir=None):
    return _load("systemconfig", cfg_dir)


# ------------------------------------------------------------------- filas
STATUS_RUN = 1    # fila ativa (idle OU rodando - o fixture manda idle como status 1 sem end_time)
STATUS_DONE = 2   # tarefa terminou (equivale a notify_queue_timeout)


class Queue:
    """Uma fila (qid). Guarda a tarefa corrente: (bid, end_time, total_time)."""

    def __init__(self, qid, qtype=1, now=real_now, purchased_endtime=-1):
        self.qid = qid
        self.qtype = qtype
        self.now = now
        self.purchased_endtime = purchased_endtime
        self.task = None          # dict(bid, start, end_time, total_time)
        self.status_code = STATUS_RUN

    def start(self, bid, qid=None, cfg_duration=0, level=None):
        """Inicia obra. cfg_duration em segundos (ex.: build_time(...)). Retorna end_time real."""
        if self.busy():
            raise RuntimeError("fila %s ocupada" % self.qid)
        t = self.now()
        dur = max(0, int(cfg_duration))
        self.task = dict(bid=bid, level=level, start=t, end_time=t + dur, total_time=dur)
        self.status_code = STATUS_RUN
        return self.task["end_time"]

    def _tick(self):
        """finish automatico ao consultar apos end_time."""
        if self.task and self.status_code == STATUS_RUN and self.now() >= self.task["end_time"]:
            self.status_code = STATUS_DONE

    def busy(self):
        self._tick()
        return bool(self.task) and self.status_code == STATUS_RUN

    def status(self):
        """Dict no formato .queue do s2c (qid/status/end_time/total_time)."""
        self._tick()
        d = {"qid": self.qid, "status": self.status_code}
        if self.task:
            d["end_time"] = self.task["end_time"]
            d["total_time"] = self.task["total_time"]
        return d

    def remaining(self):
        self._tick()
        if not self.task or self.status_code == STATUS_DONE:
            return 0
        return max(0, self.task["end_time"] - self.now())

    def speedup(self, seconds):
        """Acelera (item de tempo / ajuda de alianca). Retorna novo end_time."""
        if not self.busy():
            return None
        self.task["end_time"] -= int(seconds)
        return self.task["end_time"]

    def collect(self):
        """Resgata tarefa concluida (e libera a fila). Retorna task ou None."""
        self._tick()
        if self.task and self.status_code == STATUS_DONE:
            t, self.task = self.task, None
            self.status_code = STATUS_RUN
            return t
        return None

    def cancel(self):
        t, self.task = self.task, None
        self.status_code = STATUS_RUN
        return t

    def to_notify(self):
        """Payload de notify_queue_update (queue_map: *queue(qid))."""
        d = self.status()
        d["base"] = {"qtype": self.qtype, "purchased_endtime": self.purchased_endtime}
        return {"queue_map": [d]}


class QueueManager:
    """Conjunto de filas por tipo (qid = qtype*10000 + n, como o fixture: 10001, 40001...)."""

    def __init__(self, now=real_now):
        self.now = now
        self.queues = {}

    def add(self, qid, qtype=None):
        q = Queue(qid, qtype if qtype is not None else qid // 10000, self.now)
        self.queues[qid] = q
        return q

    def start(self, bid, qid, cfg_duration, level=None):
        return self.queues[qid].start(bid, qid, cfg_duration, level)

    def finished(self):
        """Filas que acabaram de concluir (para notify_queue_timeout)."""
        return [q for q in self.queues.values() if q.status()["status"] == STATUS_DONE and q.task]

    def snapshot(self):
        return {"queue_map": [q.to_notify()["queue_map"][0] for q in self.queues.values()]}


# --------------------------------------------------------- producao / offline
# Estacao de trabalho (produce_param): a cada ti_unit ms de trabalho sai output_after_buff.
# Fixture (notify_produced_resource_init) - 1 recurso por tipo de construcao:
#   195: 6 estacoes ti=20000 out=645 | 193: 6 x (3500, 1050) | 194: 6 x (11300, 1598)
DEFAULT_STATIONS = {
    195: [(20000, 645)] * 6,
    193: [(3500, 1050)] * 6,
    194: [(11300, 1598)] * 6,
}
# 192 (sem estacoes no fixture) e 106 (ouro) -> taxa plana calibrada (itens/s offline)
# systemconfig.furniture_output.offline_work_*_coefficient
OFFLINE_COEF = {192: 0.6892, 193: 0.6574, 194: 0.6791, 195: 0.6713, 106: 0.8}
# (taxa bruta, antes do coeficiente): ganho_fixture / (1156 s * coef)
DEFAULT_FLAT_RATES = {192: 151658 / (1156.0 * 0.6892), 106: 90 / (1156.0 * 0.8)}
# Fator de calibracao: gain = rate*secs*coef*K.  Ajustado no fixture (offline_len 1156):
# 195->0.04728, 193->0.04708, 194->0.04724 (consistente, ~0.0472). Hipotese: fracao do
# tempo em que os sobreviventes trabalham (agenda/descanso) - NAO confirmada.
OFFLINE_WORK_K = 0.0472
OFFLINE_MAX_TI = 43200        # systemconfig.offline_work_max_ti (cap 12h)
OFFLINE_MIN_LEN = 120         # survivor.offline_time_limit (abaixo disso nao ha notify)


def offline_gain(last_logout, now, stations=None, flat_rates=None, coef=None,
                 k=OFFLINE_WORK_K, law_point=0, dead_count=0, max_ti=OFFLINE_MAX_TI,
                 min_len=OFFLINE_MIN_LEN):
    """Ganho offline no formato notify_offline_info. None se offline < min_len.
    stations: {res_id: [(ti_unit_ms, output_after_buff), ...]}; flat_rates: {res_id: itens/s}."""
    length = int(now) - int(last_logout)
    if length < min_len:
        return None
    eff = min(length, max_ti)
    stations = DEFAULT_STATIONS if stations is None else stations
    flat = DEFAULT_FLAT_RATES if flat_rates is None else flat_rates
    coef = OFFLINE_COEF if coef is None else coef
    rates = {}
    for rid, ws in stations.items():
        rates[rid] = sum(out * 1000.0 / ti for ti, out in ws)
    for rid, r in flat.items():
        rates.setdefault(rid, r)
    items = []
    for rid in sorted(rates):
        cnt = int(rates[rid] * eff * coef.get(rid, 1.0) * (k if rid in stations else 1.0))
        if cnt > 0:
            items.append({"id": rid, "count": cnt})
    # ordem do fixture: 106,192,193,194,195 (ja ordenado)
    return {"items": items, "dead_count": dead_count, "offline_len": length,
            "law_point": law_point}


class Station:
    """Estacao de trabalho: acumula unidades prontas desde a ultima coleta."""

    def __init__(self, fid, ti_unit, output, now=real_now):
        self.fid, self.ti_unit, self.output, self.now = fid, ti_unit, output, now
        self.since_ms = self.now() * 1000
        self.remaining_mti = 0

    def pending(self):
        """(unidades, remaining_mti ms) acumulados (nao coletados)."""
        el = self.now() * 1000 - self.since_ms + self.remaining_mti
        return el // self.ti_unit, el % self.ti_unit

    def collect(self):
        units, rem = self.pending()
        self.since_ms = self.now() * 1000
        self.remaining_mti = rem
        return units * self.output


class SurvivorWork:
    """work_start(sid, dur) -> work_endtime; pronto_coletavel. Padrao hunter_tool: 180 s."""

    HUNTER_COOL_S = 180   # systemconfig.hunter_tool.cool_time = 180000 ms

    def __init__(self, now=real_now):
        self.now = now
        self.jobs = {}    # sid -> dict(start, work_endtime, collected)

    def work_start(self, sid, dur=HUNTER_COOL_S):
        t = self.now()
        self.jobs[sid] = dict(start=t, work_endtime=t + int(dur), collected=False)
        return t + int(dur)

    def pronto_coletavel(self, sid):
        j = self.jobs.get(sid)
        return bool(j) and not j["collected"] and self.now() >= j["work_endtime"]

    def coletar(self, sid):
        """Marca coletado; retorna segundos trabalhados ou None se ainda nao pronto."""
        if not self.pronto_coletavel(sid):
            return None
        j = self.jobs[sid]
        j["collected"] = True
        return j["work_endtime"] - j["start"]

    def to_furniture(self, sid, fid):
        j = self.jobs.get(sid)
        d = {"fid": fid}
        if j and not j["collected"]:
            d["work_endtime"] = j["work_endtime"]
            d["sid_list"] = [sid]
        return d


# -------------------------------------------------------------------- agenda
# qtime_seqment (grupo sem group_id => ids 15..21): limites em horas do dia
#  15: 0-6 sono | 16: 6-7 descanso | 17: 7-12 trabalho | 18: 12-15 livre
#  19: 15-20 trabalho | 20: 20-23 livre | 21: 23-24 descanso
QTIME_DEFAULT = [(15, 6), (16, 7), (17, 12), (18, 15), (19, 20), (20, 23), (21, 24)]
# Calibragem: fixture server_time 1795057408 -> qtime_id 21 => hora local 23:03 => UTC-4.
TZ_OFFSET_H = -4


def qtime_id(t, tz_offset_h=TZ_OFFSET_H, table=QTIME_DEFAULT, speed=1):
    """qtime_id do instante t (unix). speed=2 seria survivor.time_speed (nao usado: o
    operador viu 1 avanco/hora)."""
    sod = ((int(t) + int(tz_offset_h * 3600)) * speed) % 86400
    h = sod / 3600.0
    for qid, end in table:
        if h < end:
            return qid
    return table[-1][0]


def segment_start(t, tz_offset_h=TZ_OFFSET_H, table=QTIME_DEFAULT):
    """Unix do inicio do segmento corrente."""
    off = int(tz_offset_h * 3600)
    local = int(t) + off
    sod = local % 86400
    prev_end = 0
    for _, end in table:
        if sod < end * 3600:
            return local - sod + int(prev_end * 3600) - off
        prev_end = end
    return t


def schedule_update(now=real_now, **kw):
    """Payload de notify_schedule_update."""
    t = now()
    return {"qtime_id": qtime_id(t, **kw), "start_time": segment_start(t, **kw), "server_time": t}


def load_qtime_table(cfg_dir=None, group=None):
    """Monta a tabela (id, hora_fim) a partir de qtime_seqment.json (grupo None => ids 15..21)."""
    rows = _load("qtime_seqment", cfg_dir)
    out = []
    for k, v in sorted(rows.items(), key=lambda kv: int(kv[0])):
        if v.get("group_id") == group:
            out.append((int(k), v.get("time_end", 24)))
    return out
