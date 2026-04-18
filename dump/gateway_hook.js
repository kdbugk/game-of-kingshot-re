'use strict';
/**
 * gateway_hook.js v3
 *
 * Captura tráfego raw da porta 30101 (game gateway) e 31601 (spectator).
 *
 * Fix v3: não usa connect() hook (syscall wrapper no-hookable).
 * Em vez disso, chama getpeername() dentro de send/recv para
 * verificar se o fd está conectado a uma das portas alvo.
 * Cache de fds positivos e negativos para não chamar getpeername toda vez.
 */

const VERSION = 'gateway_hook.js v3';
const TARGET_PORTS = [30101, 31601];
const MAX_BYTES    = 512;   // bytes máximos a exibir por chamada

// cache: fd -> peer {ip, port} ou false (não é alvo)
const fdCache  = {};
// estatísticas
let sendCount  = 0;
let recvCount  = 0;

// ── getpeername nativa ────────────────────────────────────────────────────────

const libc = Process.findModuleByName('libc.so');

const _getpeername = (function () {
  const addr = libc ? libc.findExportByName('getpeername') : null;
  if (!addr) { console.log('[GW] getpeername nao encontrado'); return null; }
  return new NativeFunction(addr, 'int', ['int', 'pointer', 'pointer']);
})();

function getPeer(fd) {
  if (fd in fdCache) return fdCache[fd];
  if (!_getpeername) return (fdCache[fd] = false);
  try {
    const buf    = Memory.alloc(32);
    const lenBuf = Memory.alloc(4);
    lenBuf.writeS32(32);
    if (_getpeername(fd, buf, lenBuf) !== 0) return (fdCache[fd] = false);
    const family = buf.readU16();
    if (family !== 2) return (fdCache[fd] = false);           // só AF_INET
    const port = (buf.add(2).readU8() << 8) | buf.add(3).readU8();
    if (TARGET_PORTS.indexOf(port) === -1) return (fdCache[fd] = false);
    const ip = buf.add(4).readU8() + '.' + buf.add(5).readU8() + '.' +
               buf.add(6).readU8() + '.' + buf.add(7).readU8();
    const peer = { ip: ip, port: port };
    fdCache[fd] = peer;
    console.log('\n[GW] *** fd=' + fd + ' conectado a ' + ip + ':' + port + ' ***');
    return peer;
  } catch (e) {
    return (fdCache[fd] = false);
  }
}

// ── invalidar cache no close() ───────────────────────────────────────────────

(function hookClose() {
  const addr = libc ? libc.findExportByName('close') : null;
  if (!addr) return;
  try {
    Interceptor.attach(addr, {
      onEnter: function (args) {
        const fd = args[0].toInt32();
        if (fdCache[fd] && fdCache[fd] !== false) {
          console.log('\n[GW] CLOSE fd=' + fd + '  ' + fdCache[fd].ip + ':' + fdCache[fd].port);
        }
        delete fdCache[fd];
      }
    });
    console.log('[GW] hook: close()');
  } catch (e) {
    console.log('[GW] close hook erro: ' + e.message);
  }
})();

// ── hexdump + strings legíveis ───────────────────────────────────────────────

function hexAndAscii(arr, n) {
  n = Math.min(arr.length, n || MAX_BYTES);
  var lines = [];
  for (var i = 0; i < n; i += 16) {
    var row = arr.slice(i, i + 16);
    var hex = '';
    var asc = '';
    for (var j = 0; j < row.length; j++) {
      hex += (row[j] < 16 ? '0' : '') + row[j].toString(16) + ' ';
      asc += (row[j] >= 0x20 && row[j] < 0x7f) ? String.fromCharCode(row[j]) : '.';
    }
    var off = i.toString(16);
    while (off.length < 4) off = '0' + off;
    lines.push('  ' + off + '  ' + hex.replace(/\s$/, '').padEnd ? hex.padEnd(48) : (hex + '                                                ').slice(0, 48) + '  |' + asc + '|');
  }
  if (arr.length > MAX_BYTES) lines.push('  ... (' + arr.length + ' bytes total)');
  return lines.join('\n');
}

function extractStrings(arr, minLen) {
  minLen = minLen || 4;
  var found = [];
  var cur   = '';
  for (var i = 0; i < arr.length; i++) {
    var b = arr[i];
    if (b >= 0x20 && b < 0x7f) {
      cur += String.fromCharCode(b);
    } else {
      if (cur.length >= minLen) found.push(cur);
      cur = '';
    }
  }
  if (cur.length >= minLen) found.push(cur);
  return found;
}

function logPacket(dir, fd, peer, rawBytes) {
  var arr   = Array.from ? Array.from(rawBytes) :
              (function () { var a = []; var v = new Uint8Array(rawBytes); for (var i = 0; i < v.length; i++) a.push(v[i]); return a; })();
  var strs  = extractStrings(arr);
  var label = dir === 'S'
    ? ('\n[GW] SEND #' + sendCount + '  fd=' + fd + '  dst=' + peer.ip + ':' + peer.port + '  ' + rawBytes.byteLength + 'B')
    : ('\n[GW] RECV #' + recvCount + '  fd=' + fd + '  src=' + peer.ip + ':' + peer.port + '  ' + rawBytes.byteLength + 'B');
  console.log(label);
  if (strs.length) console.log('[GW]   strings: ' + strs.join(' | '));
  console.log(hexAndAscii(arr));
}

// ── send / recv / write / read ───────────────────────────────────────────────

(function hookIO() {
  var hooks = [
    { name: 'send',  dir: 'S', fdArg: 0, bufArg: 1, lenIsArg: false },
    { name: 'write', dir: 'S', fdArg: 0, bufArg: 1, lenIsArg: false },
    { name: 'recv',  dir: 'R', fdArg: 0, bufArg: 1, lenIsArg: false },
    { name: 'read',  dir: 'R', fdArg: 0, bufArg: 1, lenIsArg: false },
  ];

  hooks.forEach(function (h) {
    var addr = libc ? libc.findExportByName(h.name) : null;
    if (!addr) { console.log('[GW] ' + h.name + '() nao encontrado'); return; }
    try {
      Interceptor.attach(addr, {
        onEnter: function (args) {
          this.fd  = args[h.fdArg].toInt32();
          this.buf = args[h.bufArg];
          this.dir = h.dir;
        },
        onLeave: function (retval) {
          var n = retval.toInt32();
          if (n <= 0) return;
          var peer = getPeer(this.fd);
          if (!peer) return;
          if (this.dir === 'S') { sendCount++; } else { recvCount++; }
          try {
            var raw = this.buf.readByteArray(Math.min(n, MAX_BYTES + 64));
            logPacket(this.dir, this.fd, peer, raw);
          } catch (e) {
            console.log('[GW] erro ao ler buffer: ' + e.message);
          }
        }
      });
      console.log('[GW] hook: ' + h.name + '()');
    } catch (e) {
      console.log('[GW] ' + h.name + ' hook erro: ' + e.message);
    }
  });
})();

// ── sumário periódico ─────────────────────────────────────────────────────────

console.log('\n[GW] ' + VERSION + ' — hooks instalados.');
console.log('[GW] Portas alvo: ' + TARGET_PORTS.join(', '));
console.log('[GW] Abra o jogo e entre numa batalha.\n');

setInterval(function () {
  var ativos = Object.keys(fdCache).filter(function (k) { return fdCache[k] !== false; });
  if (ativos.length === 0 && sendCount + recvCount === 0) {
    console.log('[GW] aguardando conexao na porta 30101/31601...');
  } else {
    console.log('[GW] fds ativos: ' + ativos.length +
                '  send=' + sendCount + '  recv=' + recvCount);
  }
}, 10000);
