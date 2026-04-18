# MITM Setup — com.run.tower.defense

Guia para interceptar tráfego HTTPS do jogo após reinício do device.

> **Por que precisa repetir após reboot?**
> O CA do mitmproxy é instalado via `mount tmpfs` sobre `/system/etc/security/cacerts/`.
> Esse mount não sobrevive ao reinício — precisa ser refeito a cada boot.
> O arquivo `.pem` fica salvo em `C:\Users\prs\.mitmproxy\` e não precisa ser regerado.

---

## Pré-requisitos

| Item | Status |
|------|--------|
| mitmproxy instalado | `C:\Users\prs\AppData\Local\Python\pythoncore-3.14-64\Scripts\mitmdump.exe` |
| CA gerado | `C:\Users\prs\.mitmproxy\mitmproxy-ca-cert.pem` |
| Device conectado via adb | `adb devices` deve mostrar o device |
| Magisk + root | `adb shell su -c id` deve retornar `uid=0(root)` |
| PC na mesma rede Wi-Fi que o device | IP do PC: `192.168.0.84` |

---

## Passo 1 — Reinstalar o CA no device

Abre um terminal na pasta `__DUMP` e roda:

```
python mitm_setup.py
```

O script vai:
1. Detectar que o CA já existe (`c8750f0d.0`) e pular a geração
2. Fazer push do cert para `/sdcard/c8750f0d.0`
3. Criar backup dos CAs originais em `/data/local/tmp/cacerts/`
4. Montar `tmpfs` sobre `/system/etc/security/cacerts/`
5. Copiar tudo de volta + o cert do mitmproxy

**Saída esperada (sucesso):**
```
[4] Instalando c8750f0d.0 como CA de sistema (Android 10+/APEX)...
  $ adb shell su -c mkdir -p /data/local/tmp/cacerts
  $ adb shell su -c chmod 777 /data/local/tmp/cacerts
  ...
  OK: -rw-r--r-- 1 root root 1172 ... /system/etc/security/cacerts/c8750f0d.0
```

Se der erro no passo 4, rode manualmente:

```
! adb shell "su -c 'mkdir -p /data/local/tmp/cacerts && chmod 777 /data/local/tmp/cacerts'"
! adb shell "su -c 'cp /system/etc/security/cacerts/*.0 /data/local/tmp/cacerts/'"
! adb shell "su -c 'cp /sdcard/c8750f0d.0 /data/local/tmp/cacerts/'"
! adb shell "su -c 'mount -t tmpfs tmpfs /system/etc/security/cacerts'"
! adb shell "su -c 'cp /data/local/tmp/cacerts/*.0 /system/etc/security/cacerts/'"
! adb shell "su -c 'chmod 644 /system/etc/security/cacerts/*.0'"
```

**Verificar instalação:**
```
! adb shell "su -c 'ls -la /system/etc/security/cacerts/c8750f0d.0'"
```
Deve retornar: `-rw-r--r-- 1 root root 1172 ...`

---

## Passo 2 — Configurar proxy Wi-Fi no Android

Via adb (mais rápido):

```
! adb shell settings put global http_proxy 192.168.0.84:8081
! adb shell settings get global http_proxy
```

Deve retornar: `192.168.0.84:8081`

**Alternativa manual no device:**
Configurações → Wi-Fi → segurar a rede → Modificar → Avançado
- Proxy: **Manual**
- Hostname: `192.168.0.84`
- Porta: `8081`

---

## Passo 3 — Iniciar a captura

```
python mitmdump_capture.py
```

**Saída esperada:**
```
[0.0s] Iniciando captura MITM — proxy 192.168.0.84:8081
[X.Xs] [22:XX:XX] HTTP(S) proxy listening at *:8081.
```

Agora abre o jogo no device e usa normalmente.

---

## Passo 4 — Ver o tráfego

Os logs ficam em `__DUMP/traffic_<timestamp>.log` (texto) e `.mitm` (binário).

**Visualizar em tempo real:** o terminal do mitmdump já printa cada request.

**Interface web interativa** (após capturar):
```
mitmweb --rfile traffic_<timestamp>.mitm
```
Abre `http://127.0.0.1:8081` no navegador — mostra headers, body completo, filtros.

**Encerrar a captura:** `Ctrl+C` no terminal do mitmdump.

---

## Passo 5 — Remover o proxy (quando terminar)

```
! adb shell settings delete global http_proxy
```

O tmpfs some no próximo reboot automaticamente.

---

## O que é capturado

| Endpoint | Capturado? | Motivo |
|----------|------------|--------|
| `got-gm-api-formal.chosenonegames.com` | ✅ Sim | Sem certificate pinning |
| `passport-got.centurygame.com` (login) | ❌ Não | Certificate pinning no SDK |
| `ta-collector.centurygame.com` (analytics) | ❌ Não | Certificate pinning |
| `graph.facebook.com` | ❌ Não | Certificate pinning do SDK |
| `*.googleapis.com` | ❌ Não | Certificate pinning do Google |
| Gateway `:30101` (batalha) | ❌ Não | Protocolo binário via SVC direto, não HTTP |

### Endpoint confirmado aberto
```
GET /api/version/info?platform=android&version=1.9.5&kingdom=931&language=pt
Host: got-gm-api-formal.chosenonegames.com
→ 200 OK — retorna servidores de gateway, CDN, versão do hotfix
```

---

## Troubleshooting

### "port already in use"
```
! netstat -an | grep 8081
```
Se ocupada, mata o processo ou use outra porta — edite `PROXY_PORT` em `mitmdump_capture.py` e refaça o passo 2 com a nova porta.

### CA não confia (jogo não conecta com proxy ativo)
O mount do tmpfs pode ter sumido. Repita o Passo 1.

### adb não encontra o device
```
! adb kill-server
! adb start-server
! adb devices
```

### mitm_setup.py falha no passo 4
O mount do `/system/etc/security/cacerts/` pode já estar ativo de uma sessão anterior. Verifique:
```
! adb shell "su -c 'cat /proc/mounts | grep cacerts'"
```
Se aparecer `tmpfs /system/etc/security/cacerts`, o mount já existe — pule para copiar o cert diretamente:
```
! adb shell "su -c 'cp /sdcard/c8750f0d.0 /system/etc/security/cacerts/ && chmod 644 /system/etc/security/cacerts/c8750f0d.0'"
```
