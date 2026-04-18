'use strict';
/**
 * gateway_diag.js v1
 *
 * Diagnóstico: descobre TODOS os hosts/portas que o jogo conecta
 * e confirma se libunity.so chama send/recv via libc ou via SVC direta.
 *
 * Roda ANTES do gateway_hook.js para entender o ambiente.
 */

const VERSION = 'gateway_diag.js v1';

const libc   = Process.findModuleByName('libc.so');
const unity  = Process.findModuleByName('libunity.so');
const il2cpp = Process.findModuleByName('libil2cpp.so');

console.log('[DIAG] ' + VERSION);
console.log('[DIAG] libc   base=' + (libc   ? libc.base   : 'nao encontrado'));
console.log('[DIAG] unity  base=' + (unity  ? unity.base  : 'nao encontrado'));
console.log('[DIAG] il2cpp base=' + (il2cpp ? il2cpp.base : 'nao encontrado'));

// ── getpeername como NativeFunction ─────────────────────────────────────────

const _getpeername = (function () {
  const a = libc ? libc.findExportByName('getpeername') : null;
  return a ? new NativeFunction(a, 'int', ['int', 'pointer', 'pointer']) : null;
})();

// Todos os (fd, host:port) já vistos
const seenFds = {};

function checkFd(fd) {
  if (fd in seenFds) return seenFds[fd];
  if (!_getpeername) return (seenFds[fd] = null);
  try {
    const buf    = Memory.alloc(32);
    const lenBuf = Memory.alloc(4);
    lenBuf.writeS32(32);
    if (_getpeername(fd, buf, lenBuf) !== 0) return (seenFds[fd] = null);
    const family = buf.readU16();
    if (family !== 2) return (seenFds[fd] = null);
    const port = (buf.add(2).readU8() << 8) | buf.add(3).readU8();
    const ip   = buf.add(4).readU8() + '.' + buf.add(5).readU8() + '.' +
                 buf.add(6).readU8() + '.' + buf.add(7).readU8();
    const key  = ip + ':' + port;
    seenFds[fd] = key;
    console.log('[DIAG] nova conexao fd=' + fd + '  ' + key);
    return key;
  } catch (_) {
    return (seenFds[fd] = null);
  }
}

// Conta de chamadas por porta para sumário
const portCount = {};

function countPort(key) {
  if (!key) return;
  var port = key.split(':')[1];
  portCount[port] = (portCount[port] || 0) + 1;
}

// ── hook send/recv/write/read em libc ────────────────────────────────────────

var libcCallCount = 0;

['send', 'recv', 'write', 'read', 'sendto', 'recvfrom', 'sendmsg', 'recvmsg', 'writev', 'readv'].forEach(function (name) {
  var addr = libc ? libc.findExportByName(name) : null;
  if (!addr) { console.log('[DIAG] nao encontrado: libc.' + name); return; }
  try {
    Interceptor.attach(addr, {
      onEnter: function (args) { this.fd = args[0].toInt32(); },
      onLeave: function (retval) {
        var n = retval.toInt32();
        if (n <= 0) return;
        libcCallCount++;
        var key = checkFd(this.fd);
        countPort(key);
      }
    });
    console.log('[DIAG] hook libc.' + name);
  } catch (e) {
    console.log('[DIAG] erro hook libc.' + name + ': ' + e.message);
  }
});

// ── verifica se libunity.so importa send/recv da libc ───────────────────────

console.log('\n[DIAG] verificando imports de libunity.so...');
if (unity) {
  var unityImports = unity.enumerateImports();
  var netImports = unityImports.filter(function (i) {
    return ['send','recv','write','read','sendto','recvfrom','connect','socket'].indexOf(i.name) !== -1;
  });
  if (netImports.length === 0) {
    console.log('[DIAG] libunity.so NAO importa send/recv da libc — provavelmente usa SVC direto');
  } else {
    netImports.forEach(function (i) {
      console.log('[DIAG] libunity import: ' + i.name + ' @ ' + i.address);
    });
  }
} else {
  console.log('[DIAG] libunity.so nao carregada ainda');
}

// ── sumário a cada 15s ───────────────────────────────────────────────────────

console.log('\n[DIAG] rodando. Abra o jogo, entre numa batalha. Ctrl+C para ver sumário.\n');

setInterval(function () {
  console.log('\n[DIAG] ══ sumário ══  chamadas_libc=' + libcCallCount);

  var ports = Object.keys(portCount).sort(function (a, b) {
    return portCount[b] - portCount[a];
  });

  if (ports.length === 0) {
    console.log('[DIAG]   nenhuma conexao de rede vista via libc');
  } else {
    console.log('[DIAG]   portas (top 15):');
    ports.slice(0, 15).forEach(function (p) {
      console.log('[DIAG]     porta ' + p + ': ' + portCount[p] + ' chamadas');
    });
  }

  // Hosts únicos vistos
  var hosts = {};
  Object.keys(seenFds).forEach(function (fd) {
    if (seenFds[fd]) hosts[seenFds[fd]] = true;
  });
  var hostList = Object.keys(hosts);
  if (hostList.length > 0) {
    console.log('[DIAG]   hosts únicos: ' + hostList.join(', '));
  }

  console.log('');
}, 15000);
