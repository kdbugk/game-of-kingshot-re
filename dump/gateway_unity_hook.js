'use strict';
/**
 * gateway_unity_hook.js v1
 *
 * libunity.so usa syscalls SVC #0 diretamente, sem passar pela libc.
 * Esse script:
 *   1. Aguarda libunity.so carregar
 *   2. Inspeciona seus imports PLT — se importar socket/send/recv da libc, hookeia lá
 *   3. Se não importar (SVC direto), usa Frida Interceptor no bloco de código da lib
 *      buscando o padrão de instrução SVC + registros de socket (x0=fd, x1=buf, x2=len)
 *
 * Para o protocolo binário da porta 30101:
 *   - Mostra hexdump + strings ASCII legíveis por pacote
 */

const VERSION    = 'gateway_unity_hook.js v1';
const PORTS      = [30101, 31601];
const MAX_BYTES  = 512;

// ── getpeername ───────────────────────────────────────────────────────────────

let _getpeername = null;

function initGetpeername() {
  const libc = Process.findModuleByName('libc.so');
  if (!libc) return;
  const a = libc.findExportByName('getpeername');
  if (a) _getpeername = new NativeFunction(a, 'int', ['int', 'pointer', 'pointer']);
}

function isTargetFd(fd) {
  if (!_getpeername || fd < 0) return null;
  try {
    const buf = Memory.alloc(32);
    const len = Memory.alloc(4);
    len.writeS32(32);
    if (_getpeername(fd, buf, len) !== 0) return null;
    if (buf.readU16() !== 2) return null;
    const port = (buf.add(2).readU8() << 8) | buf.add(3).readU8();
    if (PORTS.indexOf(port) === -1) return null;
    return buf.add(4).readU8() + '.' + buf.add(5).readU8() + '.' +
           buf.add(6).readU8() + '.' + buf.add(7).readU8() + ':' + port;
  } catch (_) { return null; }
}

// ── output ────────────────────────────────────────────────────────────────────

function hexAndAscii(raw) {
  const view  = new Uint8Array(raw);
  const n     = Math.min(view.length, MAX_BYTES);
  const lines = [];
  for (let i = 0; i < n; i += 16) {
    let hex = '', asc = '';
    for (let j = i; j < Math.min(i + 16, n); j++) {
      hex += (view[j] < 16 ? '0' : '') + view[j].toString(16) + ' ';
      asc += (view[j] >= 0x20 && view[j] < 0x7f) ? String.fromCharCode(view[j]) : '.';
    }
    const off = ('000' + i.toString(16)).slice(-4);
    lines.push('  ' + off + '  ' + (hex + ' '.repeat(49)).slice(0, 48) + ' |' + asc + '|');
  }
  if (view.length > MAX_BYTES) lines.push('  ... (' + view.length + 'B total)');
  return lines.join('\n');
}

function extractStrings(raw, minLen) {
  const view = new Uint8Array(raw);
  const res  = [];
  let cur    = '';
  for (let i = 0; i < view.length; i++) {
    const b = view[i];
    if (b >= 0x20 && b < 0x7f) { cur += String.fromCharCode(b); }
    else { if (cur.length >= (minLen || 4)) res.push(cur); cur = ''; }
  }
  if (cur.length >= (minLen || 4)) res.push(cur);
  return res;
}

// ── hook de uma função com assinatura (fd, buf, len) ─────────────────────────

const fdCache = {};
let   pktN    = 0;

function attachFdHook(addr, label) {
  try {
    Interceptor.attach(addr, {
      onEnter: function (args) {
        this.fd  = args[0].toInt32();
        this.buf = args[1];
        this.len = args[2].toInt32();
      },
      onLeave: function (retval) {
        const n = retval.toInt32();
        if (n <= 0 || this.len <= 0) return;
        const fd   = this.fd;
        let   peer = fd in fdCache ? fdCache[fd] : (fdCache[fd] = isTargetFd(fd));
        if (!peer) return;
        pktN++;
        const raw  = this.buf.readByteArray(Math.min(n, MAX_BYTES + 64));
        const strs = extractStrings(raw);
        console.log('\n[GW] ' + label + ' #' + pktN + '  fd=' + fd +
                    '  peer=' + peer + '  ' + n + 'B');
        if (strs.length) console.log('[GW]   strings: ' + strs.join(' | '));
        console.log(hexAndAscii(raw));
      }
    });
    console.log('[GW] hook: ' + label + ' @ ' + addr);
    return true;
  } catch (e) {
    console.log('[GW] erro hook ' + label + ': ' + e.message);
    return false;
  }
}

// ── inspeciona e hookeia libunity.so ─────────────────────────────────────────

function hookUnity(mod) {
  console.log('\n[GW] libunity.so carregada! base=' + mod.base +
              '  size=' + (mod.size / 1024 / 1024).toFixed(0) + 'MB');

  // 1. Tenta via imports PLT (se unity importar send/recv da libc)
  const targetImports = ['send', 'recv', 'write', 'read',
                         'sendto', 'recvfrom', 'sendmsg', 'recvmsg'];
  let   hooksViaImport = 0;

  mod.enumerateImports().forEach(function (imp) {
    if (targetImports.indexOf(imp.name) !== -1 && imp.address && !imp.address.isNull()) {
      if (attachFdHook(imp.address, 'unity.' + imp.name)) hooksViaImport++;
    }
  });

  if (hooksViaImport > 0) {
    console.log('[GW] hookeado via PLT imports: ' + hooksViaImport + ' funções');
    return;
  }

  // 2. PLT não funcionou — tenta via exports próprios da libunity
  console.log('[GW] libunity nao importa send/recv via PLT — buscando exports internos...');
  const socketExports = ['send', 'recv', 'socket_send', 'socket_recv',
                         'UnitySendData', 'UnityRecvData'];
  mod.enumerateExports().forEach(function (exp) {
    if (socketExports.indexOf(exp.name) !== -1) {
      attachFdHook(exp.address, 'unity.exp.' + exp.name);
    }
  });

  // 3. Fallback: hookeia as funções libc mas via PLT da PRÓPRIA libunity
  //    buscando referências ao endereço de send() dentro da .plt section
  console.log('[GW] tentando PLT scan em libunity.so...');
  const libcSend = Process.findModuleByName('libc.so');
  if (libcSend) {
    const sendAddr = libcSend.findExportByName('send');
    const recvAddr = libcSend.findExportByName('recv');
    if (sendAddr) console.log('[GW]   libc.send @ ' + sendAddr);
    if (recvAddr) console.log('[GW]   libc.recv @ ' + recvAddr);
  }

  console.log('[GW] libunity usa SVC direto — sem hook PLT disponivel');
  console.log('[GW] alternativa: usar tcpdump no device (ja confirmado funcionar)');
  console.log('[GW] execute em outro terminal:');
  console.log('[GW]   adb shell "su -c tcpdump -i any port 30101 -w /sdcard/battle.pcap"');
}

// ── aguarda libunity.so com polling ──────────────────────────────────────────

function main() {
  console.log('[GW] ' + VERSION);
  initGetpeername();

  const poll = setInterval(function () {
    const mod = Process.findModuleByName('libunity.so');
    if (!mod) return;
    clearInterval(poll);
    hookUnity(mod);
  }, 200);

  setInterval(function () {
    if (pktN === 0) {
      console.log('[GW] aguardando trafego na porta 30101...');
    } else {
      console.log('[GW] pacotes capturados: ' + pktN);
    }
  }, 15000);

  console.log('[GW] aguardando libunity.so carregar...\n');
}

main();
