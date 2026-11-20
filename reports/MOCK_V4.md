# MOCK V4 — mock gateway sproto-REAL (Kingshot 1.14.27)

Stop honesta: **tudo validado offline/loopback; nada testado com o celular.** Nada escrito no repo (só leitura de `protocols/`).

## Arquivos (em `C:/Users/prs/work/mockserver/`)
| arquivo | função |
|---|---|
| `sproto_lib.py` | **encode** schema-driven (`enc_struct`), decode próprio (`dec_struct`), **0-pack** (`pack`), 0-unpack (reusa `sproto_py.unpack`), XOR 4B (`xor`), builders (`build_request/response/push`), `Peer` (casa session→protocolo), framing uint16 BE |
| `mock_v4.py` | servidor TCP (v4). `--export-fixture` gera `fixture_v4.json` do transcript |
| `fixture_v4.json` | objetos **tipados** (não bytes) extraídos do transcript: resp de login, 176 pushes do burst, 26 templates de resp, perfil, client_data |
| `val_v4.py` | validação offline contra `gw_transcript115.pkl` (copiado do WSL p/ a pasta) |
| `test_v4_client.py` | mini-cliente loopback (decodifica respostas com o **sproto_py original**) |
Dependência: `sproto_py.py` do repo (importado por path; `KS_PROTOCOLS` sobrescreve). Rodar: `python mock_v4.py [--port 30101] [--key random|ecbabcb9]`.

## Método
- **Encode** = inverso do `Dec`: struct = `u16 fc` + `fc×u16` (inline `(v+1)*2` p/ 0..0x7ffe; `0` = dado; ímpar = pula tags) + seção de dados (`u32 len + bytes`). Inteiros fora do inline: 4 B (int32) ou 8 B; arrays de inteiro/double: `sz` + valores; boolean[] = 1 B cada; string/binary(hex)/struct[] = `u32 len + dado`. Tipos aninhados resolvidos pelo `Dec.resolve` original. Campos desconhecidos (`?N`) preservados como dado cru.
- Correção vs `sproto_py.Dec`: o decoder original trata `boolean[]` e `double[]` como int com byte `sz` (boolean[] não tem `sz` no sproto padrão; double[] vira int). `dec_struct` trata certo. (Não apareceu no transcript; é só robustez.)
- **0-pack**: grupos de 8 B, bitmap + não-zeros; corrida `0xFF` p/ grupos densos (≥6 não-zeros, início com 8), máx 256.
- **Servidor**: parse do request → `Peer.parse` (tag do header sproto → nome do protocolo c2s) → handler → resposta com `session` pareada, só `session` no header (sem `type`); se request cifrado, o servidor **ecoa o `ud` do request** (inclusive `crypt_length`, que no transcript NÃO é o tamanho real da resposta: 3001 resp tem 6 B e crypt_length=2522) e XORa o corpo (sem XORar o padding do pack).
- Handlers sintéticos: heartbeat 22 `{time}` relógio sintético crescente (T0=1795057408 + segundos); login 1 (`code 0`, uid/serverid, `server_ts`, **`secret_key`**); `req_loaddata` → burst de `notify_*` re-encodados + `{code:0}`; 8501 `{code:0}`; 1029 perfil por uid pedido (template do transcript + uid/nickName); 3001 ACK `{code:0}`. **Qualquer outro request é desbloqueado**: template tipado do transcript (26 nomes) ou default `{code:0}` (só se o schema da resposta tem `code`; `{}` caso contrário; sem `response` no schema = não responde).

## ⭐ Descoberta: origem da chave XOR
O `loginauth` response (`c2s` schema, tag 17) traz **`secret_key : binary`** — no transcript = `ec ba bc b9` (exatamente a chave XOR que a lane luapkg recuperou por crib). Ou seja, **a chave é por sessão e entregue no login**, não precisa ser descoberta. O mock gera 4 B aleatórios por conexão e os manda em `secret_key` (ou `--key` fixo). Isso fecha a "pendência: origem da chave" do luapkg.md (para o `crypt_method=1`; o modo RC4 segue não observado). Hipótese não verificada com o cliente real: que ele use os 4 B de secret_key exatamente como XOR periódico — o transcript é coerente com isso (312/312 decodificam com ela).

## Validações (contagens reais)
`python val_v4.py` (transcript 312 frames, 1.14.27):
- decode schema-driven (`sproto_lib`): **312/312** com consumo exato (≤7 B de padding); 0 campos `?N` desconhecidos.
- `pack(unpack(raw)) == raw`: **312/312** (0-pack byte-idêntico ao do cliente/servidor real, incl. corridas 0xFF).
- round-trip de objeto (decode→encode→decode): **312/312**.
- **re-encode byte-exato** (header + corpo XOR re-gerados do objeto == bytes originais módulo padding): **312/312** — inclui 1029/1023/3001 cifrados (2522 B).
- round-trip das respostas sintéticas (build→pack→unpack→parse, `pack(unpack(x))==x`): **6/6** (login, heartbeat, 8501, 1029 cifrado, 3001 cifrado, loaddata).

`python test_v4_client.py` (loopback; respostas lidas com `sproto_py` ORIGINAL): **11/11**
login (secret_key recebida, session pareada) · loaddata (176 pushes + resp) · 30 heartbeats com tempo crescente · 8501 · 1029 cifrado (2 uids; ud ecoado) · 3001 cifrado 2522 B → ACK · `req_shop_info` via template · `req_climbtower_challenge` (20463, nunca visto) via default · **500 heartbeats pipelined em 0,06 s** · chave errada → não decodifica (XOR efetivo).

## Gaps / riscos
1. **Não testado com o cliente real.** Se o cliente travar de novo no loading, suspeitos: ordem/tempo do burst (hoje enviado todo de uma vez, sem os 0,2 s do original), pushes pós-t=5 s não reproduzidos, e respostas (`rank_info`, `shop_info*`, etc.) que no transcript chegam como resposta a requests específicos — aqui só saem se o cliente pedir (templates dos 26 nomes vistos).
2. Fixture é **do transcript** (dados da conta real do operador: uid, sdkToken não — só resp). O "sintético" é tipado/re-encodado, não gerado do zero; para respostas ricas (loja, rank) valores vêm do captured. Em `--fixture` inexistente o mock cai em perfil/login mínimos e **sem burst** (provavelmente insuficiente p/ o cliente).
3. Sem lógica de estado de jogo (compra, combate, 2803/20463): só `{code:0}` — o cliente pode rejeitar semântica. `20466/20474` (notify_climbtower_*) não são emitidos.
4. `crypt_method` ≠ 1 (RC4) não implementado; ud ecoado do request (se o cliente enviar `crypt_method=2`, o mock devolve ud igual mas XORa só se =1 → corpo claro).
5. Inteiros `integer(2)` (decimal fixo) tratados como int cru; sem falhas no transcript.
6. Heartbeat: relógio sintético começa em 1795057408 (nov/2026 do transcript), não em `time.time()`; trivial trocar se o cliente checar drift.
7. Parser do .sproto (`sproto_py.parse`) é do repo e frágil a comentários exóticos; passou nos 2 schemas atuais.
8. Transporte TCP puro (uint16 BE), sem TLS — mesmo do v3; DNAT/`dnat.sh` inalterado. `mock_gateway.py` v3 não foi modificado.

## Próximo passo (operador, com celular)
`python mock_v4.py --port 30101` (com DNAT ativo; log por request no stdout) → observar se loaddata→burst libera o loading dos 99%. Se travar, o log mostra o último request/`parse-fail`; ajustar pacing do burst (`h_loaddata`).
