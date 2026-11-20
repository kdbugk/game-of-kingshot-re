"""Testes de server_timers.py com relogio simulado. Rodar: python test_timers.py"""
import unittest
import server_timers as st


class Clock:
    def __init__(self, t=1795057408):
        self.t = t

    def __call__(self):
        return self.t

    def adv(self, s):
        self.t += s


class TestQueue(unittest.TestCase):
    def test_obra_cfg_real(self):
        c = Clock()
        q = st.Queue(10001, 1, c)
        dur = st.build_time(301, 6)            # castelo/fornalha nv6 = 1800 s (cfg)
        self.assertEqual(dur, 1800)
        end = q.start(301, 10001, dur)
        self.assertEqual(end, 1795057408 + 1800)
        s = q.status()
        self.assertEqual((s["status"], s["end_time"], s["total_time"]), (1, end, 1800))
        c.adv(1799)
        self.assertEqual(q.status()["status"], 1)
        self.assertEqual(q.remaining(), 1)
        c.adv(1)                               # chegou end_time -> finish automatico
        self.assertEqual(q.status()["status"], 2)
        self.assertFalse(q.busy())
        self.assertEqual(q.collect()["bid"], 301)
        self.assertNotIn("end_time", q.status())

    def test_fila_ocupada_e_speedup(self):
        c = Clock(); q = st.Queue(10001, 1, c)
        q.start(302, 10001, st.build_time(302, 10))    # 840 s
        with self.assertRaises(RuntimeError):
            q.start(303, 10001, 10)
        q.speedup(800)
        self.assertEqual(q.remaining(), 40)
        c.adv(40)
        self.assertEqual(q.status()["status"], 2)

    def test_tabelas_cfg(self):
        self.assertEqual(st.build_time(301, 30), 3472020)       # ~40,2 dias
        self.assertEqual(st.build_time(302, 1), 2)
        self.assertEqual(st.tech_time(1001, 3), 108)
        self.assertEqual(st.soldier_train_time(10100), 12)

    def test_manager(self):
        c = Clock(); m = st.QueueManager(c)
        m.add(10001); m.add(40001)
        m.start(301, 10001, 60)
        self.assertEqual(len(m.snapshot()["queue_map"]), 2)
        c.adv(61)
        self.assertEqual([q.qid for q in m.finished()], [10001])
        n = m.queues[10001].to_notify()["queue_map"][0]
        self.assertEqual(n["status"], 2); self.assertEqual(n["base"]["qtype"], 1)


class TestOffline(unittest.TestCase):
    def test_fixture_1156s(self):
        """Fixture real: offline_len 1156 -> 192:151658 193:64402 194:31471 195:7100 106:90."""
        real = {192: 151658, 193: 64402, 194: 31471, 195: 7100, 106: 90}
        out = st.offline_gain(1795057408 - 1156, 1795057408, law_point=13394)
        self.assertEqual(out["offline_len"], 1156)
        self.assertEqual(out["law_point"], 13394)
        got = {i["id"]: i["count"] for i in out["items"]}
        self.assertEqual(set(got), set(real))
        for rid, v in real.items():
            self.assertLess(abs(got[rid] - v) / v, 0.015, (rid, got[rid], v))

    def test_1h(self):
        out = st.offline_gain(1000, 1000 + 3600)
        got = {i["id"]: i["count"] for i in out["items"]}
        base = st.offline_gain(0, 1156)
        r = {i["id"]: i["count"] for i in base["items"]}
        for rid in got:   # linear no tempo
            self.assertAlmostEqual(got[rid] / r[rid], 3600 / 1156, delta=0.01 * 3600 / 1156)
        self.assertEqual(out["offline_len"], 3600)

    def test_limites(self):
        self.assertIsNone(st.offline_gain(0, 119))               # < offline_time_limit
        a = st.offline_gain(0, 43200); b = st.offline_gain(0, 10 * 86400)
        self.assertEqual(a["items"], b["items"])                 # cap 12 h
        self.assertEqual(b["offline_len"], 10 * 86400)


class TestWork(unittest.TestCase):
    def test_coleta_survivor(self):
        c = Clock(); w = st.SurvivorWork(c)
        end = w.work_start(206, 180)
        self.assertEqual(end, c() + 180)
        self.assertFalse(w.pronto_coletavel(206))
        self.assertIsNone(w.coletar(206))
        c.adv(180)
        self.assertTrue(w.pronto_coletavel(206))
        self.assertEqual(w.coletar(206), 180)
        self.assertFalse(w.pronto_coletavel(206))               # so uma vez por ciclo
        self.assertNotIn("work_endtime", w.to_furniture(206, 305000301))

    def test_estacao_producao(self):
        c = Clock(); s = st.Station(304000601, 20000, 645, c)
        c.adv(65)                                               # 65 s => 3 unidades + 5000 ms
        self.assertEqual(s.pending(), (3, 5000))
        self.assertEqual(s.collect(), 3 * 645)
        c.adv(15)                                               # 5000+15000 = 20000 => +1
        self.assertEqual(s.collect(), 645)


class TestAgenda(unittest.TestCase):
    def test_fixture_qtime21(self):
        self.assertEqual(st.qtime_id(1795057408), 21)           # fixture real
        u = st.schedule_update(Clock())
        self.assertEqual(u["qtime_id"], 21)
        self.assertEqual(u["server_time"], 1795057408)
        self.assertLessEqual(u["start_time"], 1795057395)

    def test_avanca_por_hora(self):
        t0 = 1795046400 + 4 * 3600 + 5 * 3600   # 05:00 local (UTC-4 => 09:00 UTC)
        seq = [st.qtime_id(t0 + h * 3600) for h in range(24)]
        self.assertEqual(seq[0], 15)                              # 05h sono
        self.assertEqual(seq[1], 16)                              # 06h descanso
        self.assertEqual(seq[2], 17)                              # 07h trabalho
        self.assertEqual(seq[7], 18)
        self.assertEqual(seq[10], 19)
        self.assertEqual(seq[15], 20)
        self.assertEqual(seq[18], 21)
        self.assertEqual(seq[19], 15)                              # virou o dia

    def test_tabela_da_cfg(self):
        self.assertEqual(st.load_qtime_table(), st.QTIME_DEFAULT)


if __name__ == "__main__":
    unittest.main(verbosity=2)
