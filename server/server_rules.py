"""server_rules.py — regras/validação de servidor de jogo offline (standalone, stdlib).
Códigos = errcodes.json REAL da produção. Cada check devolve código int ou None (ok)."""
import json, os

ERRCODES_PATH = os.environ.get("ERRCODES", r"C:/Users/prs/projects/game-of-kingshot-re/protocols/errcodes.json")
CFG_DIR = os.environ.get("CFG_DIR", r"C:/Users/prs/work/lua-logic/cfg")

def _load(p):
    try:
        with open(p, encoding="utf-8") as f: return json.load(f)
    except OSError: return {}

ERR = _load(ERRCODES_PATH)                       # nome -> código (3045)
ERR_NAME = {v: k for k, v in ERR.items()}
OK = 0
# fallback mínimo caso o arquivo não exista (valores reais observados)
for _k, _v in {"err_param_illegal": 2, "err_climbtower_level_already_passed": 16807}.items():
    ERR.setdefault(_k, _v)

def code(name): return ERR[name]
def name_of(c): return ERR_NAME.get(c, f"?{c}")

# ---------------------------------------------------------------- (1) sequenciador
ST_CONNECTED, ST_LOGGED, ST_LOADED = "connected", "logged_in", "loaded"
MSG_LOGIN, MSG_LOADDATA, MSG_HEARTBEAT = "req_login", "req_loaddata", "req_heartbeat"
# liberadas antes do loaddata (heartbeat sempre; fluxo de conta de login_*; client_track)
PRE_LOADDATA_OK = {"req_loaddata", "req_heartbeat", "req_spectator_agent_heartbeat",
                   "req_del_account_pre_review", "req_del_account", "req_del_account_cancel_pre_review",
                   "req_spectator_get_auth_token", "req_del_account_cancel_del_account",
                   "req_add_client_track_log"}
PRE_LOADDATA_IDS = {21, 22, 23, 24, 25, 26, 27, 28, 51}

class Session:
    def __init__(self): self.state = ST_CONNECTED
    def login_ok(self):
        if self.state == ST_CONNECTED: self.state = ST_LOGGED
    def check(self, msg):
        """msg = nome (req_*) ou id c2s. Retorna código de erro ou None (e avança o estado em loaddata)."""
        n = msg
        if n in (MSG_HEARTBEAT, 22, "req_spectator_agent_heartbeat", 51): return None
        if n in (MSG_LOADDATA, 21):
            if self.state == ST_CONNECTED: return code("err_param_illegal")   # loaddata sem login
            self.state = ST_LOADED; return None
        if self.state == ST_LOADED: return None
        if n in PRE_LOADDATA_OK or n in PRE_LOADDATA_IDS: return None
        return code("err_param_illegal")          # ação antes do loaddata -> 2

# ---------------------------------------------------------------- (2) anti-replay
# kind -> erro (nomes reais)
REPLAY_ERR = {
    "climbtower_level": "err_climbtower_level_already_passed",     # 16807
    "climbtower_reward": "err_climbtower_already_rewarded",        # 16791
    "daily_task_reward": "err_daily_task_act_already_get",         # 10522
    "daily_integral_reward": "err_daily_integral_reveived",        # 903
    "daily_all": "err_daily_all_reveived",                         # 905
    "vip_daily_exp": "err_vip_daily_exp_today_get",                # 4501
    "month_card_reward": "err_month_card_already_collect_reward",  # 3602
    "mail_attach": "err_mail_attach_has_receive",                  # 1202
    "reward_generic": "err_reward_received",                       # 6158
    "bind_account_reward": "err_bind_account_already_received",
    "accumulative_reward": "err_accumulative_already_received",
    "fund_free_reward": "err_fund_free_reward_collected",
    "fund_reward": "err_fund_reward_collected",
    "alliance_dev_daily": "err_alliance_dev_already_get_daily_reward",
    "fishing_daily": "err_fishing_has_get_daily_reward",
    "battle_pass_buy": "err_battle_pass_already_buy",
}
DAILY_KINDS = {"daily_task_reward", "daily_integral_reward", "daily_all", "vip_daily_exp",
               "alliance_dev_daily", "fishing_daily"}

class ReplayRegistry:
    def __init__(self): self._done = {}
    def mark_done(self, kind, key):
        if kind not in REPLAY_ERR: raise KeyError(f"kind desconhecido: {kind}")
        self._done.setdefault(kind, set()).add(key)
    def check(self, kind, key):
        if kind not in REPLAY_ERR: return None
        return code(REPLAY_ERR[kind]) if key in self._done.get(kind, ()) else None
    def check_and_mark(self, kind, key):
        e = self.check(kind, key)
        if e is None: self.mark_done(kind, key)
        return e
    def reset_daily(self):
        for k in DAILY_KINDS: self._done.pop(k, None)
    def dump(self): return {k: sorted(map(str, v)) for k, v in self._done.items()}

# ---------------------------------------------------------------- (3) lojas
_RESET_CYCLES = {"NONE", "DAY", "WEEK", "MONTH"}

def _load_goods():
    g = {}
    for fn in ("fixed_store", "store_item_sp_conf", "threedays_shop_item"):
        for gid, v in _load(os.path.join(CFG_DIR, fn + ".json")).items():
            if isinstance(v, dict):
                g.setdefault(str(gid), {"item_id": v.get("item_id"), "limit_num": v.get("limit_num"), "price": v.get("price"),
                                        "currency": v.get("currency"), "store": v.get("store_type", v.get("table_id")),
                                        "src": fn})
    return g
GOODS = _load_goods()
SHOPS = set(map(str, _load(os.path.join(CFG_DIR, "store_conf.json")).keys()))

def shop_limit(goods_id):
    g = GOODS.get(str(goods_id)); return None if g is None else g["limit_num"]

def check_shop_buy(shop_id, goods_id, count, buy_count_atual, reset_cycle="NONE", goods=None, limit_override=None):
    """Valida compra. reset_cycle (DAY/WEEK/MONTH/NONE) é apenas informativo: o chamador
    zera buy_count_atual na virada do ciclo (ver ShopState)."""
    if reset_cycle not in _RESET_CYCLES: return code("err_param_illegal")
    if not isinstance(count, int) or count <= 0: return code("err_param_illegal")
    g = (goods or GOODS).get(str(goods_id))
    if g is None: return code("err_shop_not_found_goods")        # 701
    lim = limit_override if limit_override is not None else g["limit_num"]
    if lim is not None and buy_count_atual + count > lim:
        return code("err_shop_buy_count_not_enough")              # 702
    return None

class ShopState:
    """contadores por (shop,goods) com ciclo de reset."""
    def __init__(self): self.c = {}
    def count(self, shop, goods): return self.c.get((str(shop), str(goods)), (0, "NONE"))[0]
    def buy(self, shop, goods, count, reset_cycle="NONE"):
        e = check_shop_buy(shop, goods, count, self.count(shop, goods), reset_cycle)
        if e is None: self.c[(str(shop), str(goods))] = (self.count(shop, goods) + count, reset_cycle)
        return e
    def reset(self, cycle):
        for k in [k for k, v in self.c.items() if v[1] == cycle]: del self.c[k]

# ---------------------------------------------------------------- (4) custos
def check_cost(recursos, custo):
    """recursos/custo: {id_recurso: qtd}. Falta -> err_item_not_enough (51)."""
    for rid, need in custo.items():
        if need < 0: return code("err_param_illegal")
        if recursos.get(rid, 0) < need: return code("err_item_not_enough")
    return None

def apply_cost(recursos, custo):
    e = check_cost(recursos, custo)
    if e is None:
        for rid, need in custo.items(): recursos[rid] = recursos.get(rid, 0) - need
    return e

# ---------------------------------------------------------------- pipeline
class RulesEngine:
    def __init__(self): self.session = Session(); self.replay = ReplayRegistry(); self.shop = ShopState()
