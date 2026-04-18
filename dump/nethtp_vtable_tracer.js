'use strict';
/**
 * nethtp_vtable_tracer.js v4
 *
 * Abordagem indireta: não hookeia nenhuma função dentro de libNetHTProtect.so
 * (libnesec monitora a integridade do código dessa lib e mata o processo em ~8s).
 *
 * A vtable em DAT_005a62e8 (offset 0x4a62e8) é uma abstração de stream:
 *   +0x160 alloc       → libc.malloc   (utilitário)
 *   +0x168 free        → libc.free     (utilitário)
 *   +0x180 write       → libc.write    (escrita de chunks — NÃO hookear, flood)
 *   +0x558 input       → libc.read/etc (leitura — NÃO hookear, quebra processo)
 *   +0x5c0 pointer     → libc          (utilitário)
 *   +0x600 release     → libil2cpp.so  ← único callback IL2CPP, hookear aqui
 *   +0x680 write_final → libc.write    (NÃO hookear)
 *
 * release (+0x600) é chamado quando o payload completo está pronto para o IL2CPP.
 * a0 deve conter o ponteiro do stream/struct com os dados serializados.
 */

const VERSION = 'nethtp_vtable_tracer.js v4';

// Offset do ponteiro da vtable na seção .data de libNetHTProtect
// DAT_005a62e8, Ghidra base 0x100000 → offset = 0x5a62e8 - 0x100000 = 0x4a62e8
const VTABLE_PTR_OFFSET = 0x4a62e8;

const SLOT_RELEASE     = 0x600;  // libil2cpp.so — callback de entrega
const SLOT_WRITE_FINAL = 0x680;  // libc — NÃO hookear

const MAX_DUMP = 512;

// ── Utilitários ───────────────────────────────────────────────────────────────

function tryReadStr(ptr) {
  if (!ptr || ptr.isNull()) return null;
  try { return ptr.readUtf8String(512); } catch (_) {}
  try { return ptr.readUtf16String(256); } catch (_) {}
  return null;
}

function hexdump16(ptr, size) {
  size = Math.min(size || 64, MAX_DUMP);
  const lines = [];
  for (let i = 0; i < size; i += 16) {
    const n = Math.min(16, size - i);
    let hex = '', asc = '';
    for (let j = 0; j < n; j++) {
      try {
        const b = ptr.add(i + j).readU8();
        hex += ('0' + b.toString(16)).slice(-2) + ' ';
        asc += (b >= 32 && b < 127) ? String.fromCharCode(b) : '.';
      } catch (_) { hex += '?? '; asc += '?'; }
    }
    lines.push('  ' + ('000' + i.toString(16)).slice(-4) + '  ' +
               hex.padEnd(48) + ' ' + asc);
  }
  return lines.join('\n');
}

function moduleOf(addr) {
  try {
    const m = Process.findModuleByAddress(addr);
    return m ? m.name : '?';
  } catch (_) { return '?'; }
}

// Verifica se endereço é código user-space ARM64 válido (não é libc/kernel/null)
function isValidCodePtr(ptr) {
  if (!ptr || ptr.isNull()) return false;
  try {
    const hi = ptr.shr(32).toInt32();
    if (hi < 0x40 || hi > 0x7fff) return false;
    return Process.findModuleByAddress(ptr) !== null;
  } catch (_) { return false; }
}

// ── Leitura e dump da struct de stream ────────────────────────────────────────

// Tenta encontrar dados reais dentro da struct de stream apontada por ptr.
// A struct contém o buffer serializado em algum offset — procura por bytes não-zero.
function dumpStreamStruct(ptr) {
  if (!ptr || ptr.isNull()) return;
  console.log('  stream struct @ ' + ptr + ':');

  // Lê os primeiros 8 ponteiros (cabeçalho) para orientação
  for (let i = 0; i < 8; i++) {
    try {
      const field = ptr.add(i * 8).readPointer();
      const mod = moduleOf(field);
      if (mod !== '?') {
        console.log('    [+0x' + (i * 8).toString(16).padStart(2, '0') + '] ' +
                    field + '  (' + mod + ')');
      }
    } catch (_) {}
  }

  // Procura por um campo que pareça ser um buffer de dados (não-zero, não ponteiro de código)
  for (let off = 0; off < 0x80; off += 8) {
    let bufPtr;
    try { bufPtr = ptr.add(off).readPointer(); } catch (_) { continue; }
    if (!bufPtr || bufPtr.isNull()) continue;
    if (isValidCodePtr(bufPtr)) continue; // é ponteiro de código, não dados

    // Tenta ler como buffer
    let b0;
    try { b0 = bufPtr.readU8(); } catch (_) { continue; }
    if (b0 === 0) continue; // provavelmente null-padding

    console.log('  possível buffer @ [+0x' + off.toString(16) + '] = ' + bufPtr + ':');
    try { console.log(hexdump16(bufPtr, 128)); } catch (_) {}
    const s = tryReadStr(bufPtr);
    if (s && s.length > 3) console.log('  str: "' + s.slice(0, 300) + '"');
    break;
  }
}

// ── Hook via vtable ───────────────────────────────────────────────────────────

function hookViaVtable(nethtpMod, attempt) {
  attempt = attempt || 1;
  const vtablePtrAddr = nethtpMod.base.add(VTABLE_PTR_OFFSET);

  let vtable;
  try { vtable = vtablePtrAddr.readPointer(); } catch (e) {
    console.log('[!] leitura vtable: ' + e.message);
    return;
  }

  if (!vtable || vtable.isNull()) {
    if (attempt === 1) console.log('[VT] vtable ainda null, aguardando...');
    setTimeout(() => hookViaVtable(nethtpMod, attempt + 1), 500);
    return;
  }

  // Aguarda release ser preenchido com uma função de libil2cpp.so
  let releasePtr;
  try { releasePtr = vtable.add(SLOT_RELEASE).readPointer(); } catch (_) {}

  if (!isValidCodePtr(releasePtr) || moduleOf(releasePtr) !== 'libil2cpp.so') {
    if (attempt % 10 === 1)
      console.log('[VT] tentativa ' + attempt + ': release ainda não é libil2cpp (' +
                  releasePtr + '  ' + moduleOf(releasePtr) + '), aguardando...');
    setTimeout(() => hookViaVtable(nethtpMod, attempt + 1), 500);
    return;
  }

  // release está pronto — loga estado completo da vtable
  console.log('[VT] vtable pronta @ ' + vtable + '  (tentativa ' + attempt + ')');
  const slotNames = {
    0x160: 'alloc', 0x168: 'free',    0x180: 'write',
    0x558: 'input', 0x5c0: 'pointer', 0x600: 'release', 0x680: 'write_final',
  };
  for (const [off, name] of Object.entries(slotNames)) {
    try {
      const fn = vtable.add(Number(off)).readPointer();
      const mark = (Number(off) === SLOT_RELEASE) ? '  ← HOOKANDO' : '';
      console.log('  [+0x' + Number(off).toString(16).padStart(3, '0') + '] ' +
                  name.padEnd(12) + ' → ' + fn + '  (' + moduleOf(fn) + ')' + mark);
    } catch (_) {}
  }
  console.log('');

  // Hook: release (+0x600) — único callback IL2CPP, payload pronto
  const nethtpStart = nethtpMod.base;
  const nethtpEnd   = nethtpMod.base.add(nethtpMod.size);
  let releaseCount  = 0;

  try {
    Interceptor.attach(releasePtr, {
      onEnter(args) {
        // Filtra: só loga se o chamador for de libNetHTProtect
        const from = moduleOf(this.returnAddress);
        if (from !== 'libNetHTProtect.so') return;

        releaseCount++;
        console.log('\n[VT] ══ release #' + releaseCount + ' ══' +
                    '  a0=' + args[0] + '  a1=' + args[1] +
                    '  a2=' + args[2] + '  a3=' + args[3] +
                    '  caller=' + this.returnAddress + '  (' + from + ')');

        // a0 pode ser o stream struct
        if (args[0] && !args[0].isNull()) dumpStreamStruct(args[0]);

        // Tenta todos os args como ponteiros de buffer
        for (let i = 1; i < 4; i++) {
          if (!args[i] || args[i].isNull()) continue;
          let size = 0;
          try { size = args[i].toInt32(); } catch (_) { continue; }
          if (size > 0 && size < 0x10000) {
            // Parece ser um tamanho — tenta ler o arg anterior como buffer
            const buf = args[i - 1];
            if (buf && !buf.isNull() && !isValidCodePtr(buf)) {
              console.log('  buffer (size=' + size + ') @ a' + (i-1) + ':');
              try { console.log(hexdump16(buf, Math.min(size, MAX_DUMP))); } catch (_) {}
            }
          }
        }
      }
    });
    console.log('[VT] hook: release @ ' + releasePtr + '  (' + moduleOf(releasePtr) + ')');
  } catch (e) {
    console.log('[!] hook release: ' + e.message);
  }
}

// ── Main ──────────────────────────────────────────────────────────────────────

function main() {
  console.log('[VT] ' + VERSION + ' iniciando...');
  console.log('[VT] aguardando libNetHTProtect.so...');

  const poll = setInterval(() => {
    const mod = Process.findModuleByName('libNetHTProtect.so');
    if (!mod) return;
    clearInterval(poll);
    console.log('[VT] base=' + mod.base + '  size=' + (mod.size / 1024).toFixed(0) + 'KB');
    hookViaVtable(mod, 1);
  }, 100);
}

main();
