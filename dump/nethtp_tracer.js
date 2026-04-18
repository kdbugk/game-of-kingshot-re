'use strict';
/**
 * nethtp_tracer.js v5
 *
 * Hooks diretos em funções internas da libNetHTProtect.so:
 *   - engine_central   (offset 0x23d5a0) — engine principal
 *   - marshal_payload  (offset 0x23acfc) — serializa payload para IL2CPP
 *   - pipeline_coleta  (offset 0x9ed9c)  — coleta fingerprint / hashes MD5
 *
 * Removidos por causarem crash detectável pelo libnesec:
 *   - JNI_OnLoad hook (v5): export público — libnesec verifica integridade do código
 *   - JNI vtable hooks (v4): modificação do libart.so detectada em ~8s
 */

// ── Offsets libNetHTProtect (Ghidra base 0x100000) ───────────────────────────
const NETHTP_OFFSETS = {
  engine_central:  0x23d5a0,
  marshal_payload: 0x23acfc,
  pipeline_coleta: 0x9ed9c,
};

const VERSION  = 'nethtp_tracer.js v8';
const MAX_DUMP = 128;

// ── Utilitários ───────────────────────────────────────────────────────────────

function tryReadCStr(ptr, max) {
  if (!ptr || ptr.isNull()) return null;
  try { return ptr.readCString(max || 256); } catch (_) { return null; }
}

function tryReadStr(ptr) {
  if (!ptr || ptr.isNull()) return null;
  try { return ptr.readUtf8String(256); } catch (_) {}
  try { return ptr.readUtf16String(128); } catch (_) {}
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

// ── A) Hooks diretos libNetHTProtect ─────────────────────────────────────────

function hookNetHTPFunctions(mod) {
  const base = mod.base;

  const attach = (name, offset, onEnterFn, onLeaveFn) => {
    try {
      const fn = base.add(offset);
      Interceptor.attach(fn, {
        onEnter: onEnterFn || function(args) {
          console.log('[NETHTP] ' + name + ' ENTER  a0=' + args[0] + ' a1=' + args[1]);
        },
        onLeave: onLeaveFn || function(retval) {
          console.log('[NETHTP] ' + name + ' LEAVE  ret=' + retval);
        }
      });
      console.log('[NETHTP] hook: ' + name + ' @ ' + fn);
    } catch (e) {
      console.log('[!] ' + name + ': ' + e.message);
    }
  };

  attach('engine_central', NETHTP_OFFSETS.engine_central,
    function(args) {
      console.log('\n[NETHTP] engine_central ENTER');
      for (let i = 0; i < 4; i++) {
        const s = tryReadStr(args[i]);
        if (s) console.log('  args[' + i + ']="' + s + '"');
      }
      try { console.log('  a0 dump:\n' + hexdump16(args[0], 48)); } catch (_) {}
    },
    function(retval) {
      console.log('[NETHTP] engine_central LEAVE  ret=' + retval);
    }
  );

  // marshal_payload desativado em v8 — testando engine_central sozinho
  // attach('marshal_payload', NETHTP_OFFSETS.marshal_payload, ...);

  // pipeline_coleta desativado desde v7
  // attach('pipeline_coleta', NETHTP_OFFSETS.pipeline_coleta, ...);
}

// ── B) JNI_OnLoad REMOVIDO ────────────────────────────────────────────────────
// JNI_OnLoad é o export público da lib — libnesec provavelmente faz hash dos
// primeiros bytes desse símbolo como verificação de integridade. Instalar um
// trampoline lá aciona a detecção (~10s → process-terminated).
// Os hooks internos por offset não são exports, portanto menos monitorados.

// ── Main ──────────────────────────────────────────────────────────────────────

function main() {
  console.log('[NETHTP] ' + VERSION + ' iniciando...');
  console.log('[NETHTP] aguardando libNetHTProtect.so...');

  const poll = setInterval(() => {
    const mod = Process.findModuleByName('libNetHTProtect.so');
    if (!mod) return;
    clearInterval(poll);
    console.log('[NETHTP] base=' + mod.base + '  size=' + (mod.size/1024).toFixed(0) + 'KB');
    hookNetHTPFunctions(mod);
  }, 100);
}

main();
