# RELATÓRIO — LANE TIMERS (módulo de tempo do servidor-lab)

Entregues (nada escrito no repo): `server_timers.py`, `test_timers.py` (12 testes, todos OK: `python test_timers.py`), este relatório.
Standalone, relógio injetável (`now=callable`, padrão `int(time.time())`). Lê as cfg de `KS_CFG_DIR` (padrão `C:/Users/prs/work/lua-logic/cfg`).

## 1. Cfg de tempo encontradas
| Sistema | Arquivo / campo | Observação |
|---|---|---|
| Construção | `build301..414.json`, campo **`costTime`** (s) + `costRes` | linha identificada por `blv` (a chave NÃO é o nível em todas: build301 chave=blv+1, build302 chave=blv). `costTime` da linha blv=N = tempo para chegar ao nível N |
| Pesquisa | `technology_detail_config.json`, campo **`cost_time`** (s) | chave = `str(tech_id)+str(nivel)` (ex. tech 1001 nv2 → `"10012"`); 190 techs |
| Pesquisa fogo-cristal | `firecrystal_technology_conf.json` `cost_time` (28800 s…) | não ligado ao módulo |
| Tropas | `soldiers.json` `training_time` (T1=12, 17, 24, 32, 44, 60, 83, 113, 131, 152 s/soldado) | só lido (`soldier_train_time`) |
| Cura | `systemconfig.infirmary`: `doctor_cure_ti=5`, `cure_factor=0.06`, `health_time_min/max=7000/13000`; `hospital.basic_wounded_soldier_limit=1000` | **não há tabela de tempo de cura por tier** achada (só fator) |
| Caça/trabalho | `systemconfig.hunter_tool.cool_time=180000` ms (180 s) — usado como duração padrão de `work_start`; `survivors_gain.time=600`; `max_hang_up_time=32400` (9 h de hang da aventura) | |
| Offline | `systemconfig.furniture_output`: `offline_work_{meat .6892, wood .6574, coal .6791, iron .6713, gold .8}_coefficient`, `offline_work_max_ti=43200` (12 h); `survivor.offline_time_limit=120` (mínimo p/ notify) | |
| Agenda | `qtime_seqment.json` (ids 15..21 = grupo sem group_id); `survivor.time_of_day=1440`, `time_speed=2`, `qtime_id_init=3` | |
| Filas | `build_queue.json` só tem presente/país (sem tempo) | |

### Tabela nível → tempo (construção)
**Build 301 (fornalha/castelo)** — nv1 0s · nv3 60s · nv6 1800s · nv9 4h30 · nv12 9h · nv15 18h · nv18 1d19h53 (157980s) · nv21 4d11h · nv24 13d2h · nv27 25d8h · **nv30 3472020s = 40d4h** · nv31 604800s (7d, tabela muda de regra) · nv36 777600s (9d).
**Build 302 (serraria; 303/304 idênticas)** — nv1 2s · nv4 35s · nv7 285s · nv10 840s · nv13 1560s · nv16 4380s · nv19 9480s · nv22 23100s · nv25 63390s · nv28 100620s · nv30 138840s.
**Pesquisa** — tech 1001: nv1 2s, nv2 40s, nv3 108s · tech 1002: 13/20/54s · tech 3090 (cadeia longa): 325000, 325000, 357500, 568750, 682500, 1625000 s.
Build 321 (quartel): 2, 9, 45, 135, 270, 540, 1080, 1620, 2430, 3240s (nv1..10).

## 2. Modelo implementado
* **Queue**: `start(bid, qid, cfg_duration)` → `end_time = now+dur`; `status()` → `{qid,status,end_time,total_time}`; consulta após `end_time` vira `status=2` (finish automático, equivale a `notify_queue_timeout`); `collect()` libera a fila; `speedup(s)`; `to_notify()` = payload `notify_queue_update`; `QueueManager` com `snapshot()` (`notify_queue_info`) e `finished()`.
* **Offline** (`offline_gain(logout, now, ...)`): ganho = Σ estações(`output_after_buff·1000/ti_unit`)·min(len,43200)·coef·K. Retorna `None` se `len<120`. Formato `notify_offline_info` (`items`, `dead_count`, `offline_len`, `law_point`).
  * **Calibração (fixture 1156 s)**: dados reais de estações (`notify_produced_resource_init`: 195 = 6×(20000ms,645), 193 = 6×(3500,1050), 194 = 6×(11300,1598)) deram ganho real / (taxa·1156·coef) = **0,04728 / 0,04708 / 0,04724 → K=0,0472** (consistente entre 3 recursos ⇒ fator global real, ainda sem origem explicada). Resultado reproduz o fixture com erro ≤0,25 % (193: 64565 vs 64402; 194: 31440 vs 31471; 195: 7087 vs 7100); 192 (meat, sem estações no fixture) e 106 (ouro) via taxa plana ajustada → exatos (151658 / 90).
  * Verificação cruzada: `logout_ts`=1795056251 e `servertime`=1795057408 → 1157 s ≈ `offline_len` 1156 (offline_len = now − logout_ts).
* **Trabalho/coleta**: `SurvivorWork.work_start(sid, dur=180)` → `work_endtime`; `pronto_coletavel`; `coletar` só uma vez por ciclo (comentário do proto: hunter tool trabalha uma vez por ciclo). `Station`: acumula unidades por `ti_unit` ms e guarda `remaining_mti` (sobra em ms), igual ao proto.
* **Agenda**: `qtime_id(t)` a partir de `qtime_seqment` (0–6 sono=15, 6–7 descanso=16, 7–12 trabalho=17, 12–15=18, 15–20 trabalho=19, 20–23=20, 23–24 descanso=21), 1 mudança/hora-limite. `schedule_update()` → `{qtime_id,start_time,server_time}`.
  * Calibrado no fixture: `server_time 1795057408` → `qtime_id 21` ⇒ hora local 23:03 ⇒ **TZ −4 h** (`TZ_OFFSET_H`). `start_time` real do fixture = 1795057395 (13 s antes de server_time), meu start = 23:00 local (1795057200).

## 3. Testes (12/12)
obra cfg real (build301 nv6=1800s: end_time, status 1→2 no limite, collect), fila ocupada + speedup, tabelas cfg (301 nv30=3472020, tech 1001 nv3=108, soldado=12), manager, offline fixture 1156 s (≤1,5 %), offline 1 h (linear), limites (<120 s → None, cap 12 h), coleta de sobrevivente, estação (65 s → 3 unid + 5000 ms; +15 s → +1), qtime fixture (=21), avanço por hora (15→16→17→18→19→20→21→15), tabela da cfg == tabela embutida.

## 4. Gaps / riscos
1. **Transcript 115 (`gw_transcript115.pkl`) é fio cifrado (sproto + XOR)**; usei o **`fixture_v4.json`** (login real decodificado) como verdade. Não achei `notify_queue_update` com `end_time` de obra no fixture: todas as filas vêm `status:1` sem end_time (ociosas) → **semântica "status 1=run, 2=done" é suposição**; o idle real é status 1 sem end_time (replicado). Falta captura de uma obra viva para confirmar o código de status "ocupada" e `help_id`.
2. `K=0,0472` é fit empírico; hipótese (fração do tempo em que os sobreviventes trabalham pela agenda, ou escala `time_speed`) **não confirmada**. Com um segundo logout de outra duração/hora daria para validar se K varia com a agenda. Não modelei sobreviventes dormindo/doentes nem buffs; `law_point` offline e `dead_count` entram como parâmetro (fixture 13394 / 0).
3. `qtime_id`: TZ −4 h é inferido de UMA amostra; `time_speed=2` da cfg sugeriria dia de jogo de 12 h, mas o operador viu 1/hora → implementado `speed=1` (parâmetro disponível).
4. Cura por tier, caça (duração de hang além de `max_hang_up_time` 9h/`hang_start_time`) e treino de tropas: só constantes lidas, sem modelo; `costTime` após nv30 do castelo muda de escala (604800 s no nv31) — pode ser outra tabela (fogo-cristal) e deve ser conferido contra captura.
5. Redutores (VIP, buffs de construção, ajuda de aliança `basic_help_reduce_time=10`) não aplicados; `speedup()` aceita segundos livres.
