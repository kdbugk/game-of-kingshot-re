/**
 * explorer.js — Análise Exploratória do Kingshot (com.run.tower.defense)
 *
 * OBJETIVO: Apenas observar e mapear estruturas internas do processo.
 * Sem hooks de bypass, sem patches, sem modificação de memória.
 * Respeita o tempo natural de vida do processo (~60s).
 *
 * Uso: frida -U -f com.run.tower.defense -l explorer.js --no-pause
 */

'use strict';

// ─── Configuração ─────────────────────────────────────────────────────────────

const TARGET_PKG  = 'com.run.tower.defense';
const NESEC_NAME  = 'libnesec.so';
const NETHTP_NAME = 'libNetHTProtect.so';
const IL2CPP_NAME = 'libil2cpp.so';
const UNITY_NAME  = 'libunity.so';

// Offsets Ghidra (base 0x100000)
const NESEC_OFF = {
  FUN_698f4:  0x598f4,   // coleta de dados do sistema
  FUN_554c:   0xf54c,    // retorna nível de detecção
  FUN_3e339c: 0x2e339c,  // loop TracerPid
  FUN_3e3494: 0x2e3494,  // loop TracerPid redundante
  FUN_b8f88:  0xab8f88,  // thread extra de detecção
  FUN_406168: 0x306168,  // ação de kill
  FUN_003811bc: 0x2811bc, // singleton getter de struct de detecção
  DAT_43b833: 0x33b833,  // flag de detecção
  DAT_43b8dc: 0x33b8dc,  // PID do tracer
};

const NETHTP_OFF = {
  FUN_0033d5a0: 0x232d5a0, // engine central
  FUN_0033acfc: 0x232acfc, // marshal/serialização
};

// ─── Utilitários ──────────────────────────────────────────────────────────────

function log(tag, msg) {
  console.log(`[${tag}] ${msg}`);
}

function tryRead(ptr, size) {
  try { return ptr.readByteArray(size); } catch(_) { return null; }
}

function hexdump16(ptr) {
  try {
    const b = ptr.readByteArray(16);
    if (!b) return '(ilegível)';
    return Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2,'0')).join(' ');
  } catch(_) { return '(ilegível)'; }
}

function getModule(name) {
  try { return Process.getModuleByName(name); } catch(_) { return null; }
}

// ─── Mapeamento de módulos ────────────────────────────────────────────────────

function mapModules() {
  log('MAP', '=== Módulos carregados ===');
  const mods = Process.enumerateModules();
  mods.forEach(m => {
    log('MAP', `${m.name.padEnd(40)} base=${m.base}  size=${m.size}`);
  });
  log('MAP', `Total: ${mods.length} módulos`);
}

// ─── Análise de exports ───────────────────────────────────────────────────────

function mapExports(modName) {
  const mod = getModule(modName);
  if (!mod) { log('EXP', `${modName} não encontrado`); return; }
  log('EXP', `=== Exports de ${modName} (base=${mod.base}) ===`);
  const exps = mod.enumerateExports();
  exps.slice(0, 30).forEach(e => {
    log('EXP', `  ${e.name.padEnd(50)} @ ${e.address}`);
  });
  if (exps.length > 30) log('EXP', `  ... +${exps.length - 30} exports omitidos`);
}

// ─── Análise de imports ───────────────────────────────────────────────────────

function mapImports(modName) {
  const mod = getModule(modName);
  if (!mod) return;
  log('IMP', `=== Imports de ${modName} ===`);
  const imps = mod.enumerateImports();
  imps.slice(0, 20).forEach(i => {
    log('IMP', `  ${i.name.padEnd(40)} de ${i.module || '?'}`);
  });
}

// ─── Observação de funções de coleta (somente leitura) ───────────────────────

function observeNesec() {
  const mod = getModule(NESEC_NAME);
  if (!mod) { log('NESEC', 'libnesec não encontrada'); return; }

  const base = mod.base;
  log('NESEC', `base=${base}  size=${mod.size}`);

  // Observar FUN_698f4 — coleta de dados
  try {
    const fn698 = base.add(NESEC_OFF.FUN_698f4);
    Interceptor.attach(fn698, {
      onEnter(args) {
        log('NESEC', `FUN_698f4 chamada — arg0=${args[0]} arg1=${args[1]}`);
      },
      onLeave(ret) {
        log('NESEC', `FUN_698f4 retornou ${ret}`);
      }
    });
    log('NESEC', `hook FUN_698f4 @ ${fn698}`);
  } catch(e) { log('NESEC', `FUN_698f4 hook err: ${e.message}`); }

  // Observar FUN_554c — nível de detecção
  try {
    const fn554 = base.add(NESEC_OFF.FUN_554c);
    Interceptor.attach(fn554, {
      onLeave(ret) {
        log('NESEC', `FUN_554c retornou nível=${ret.toInt32()} (0=ok, >0=detectado)`);
      }
    });
    log('NESEC', `hook FUN_554c @ ${fn554}`);
  } catch(e) { log('NESEC', `FUN_554c hook err: ${e.message}`); }

  // Leitura dos campos de estado da struct de detecção (sem modificar)
  setInterval(() => {
    try {
      const flagAddr   = base.add(NESEC_OFF.DAT_43b833);
      const tracerAddr = base.add(NESEC_OFF.DAT_43b8dc);
      const flag   = flagAddr.readU8();
      const tracer = tracerAddr.readS32();
      if (flag !== 0 || tracer !== 0) {
        log('NESEC', `DAT flag=${flag}  TracerPID=${tracer}`);
      }
    } catch(_) {}
  }, 3000);
}

// ─── Observação do marshaler de payload ──────────────────────────────────────

function observeNetHTProtect() {
  const mod = getModule(NETHTP_NAME);
  if (!mod) { log('NETHTP', 'libNetHTProtect não encontrada'); return; }

  const base = mod.base;
  log('NETHTP', `base=${base}  size=${mod.size}`);

  // Observar engine central
  try {
    const fnEngine = base.add(NETHTP_OFF.FUN_0033d5a0);
    Interceptor.attach(fnEngine, {
      onEnter(args) {
        log('NETHTP', `engine chamada — param1=${args[0]} param8=${args[7]} param9=${args[8]}`);
      },
      onLeave(ret) {
        log('NETHTP', `engine retornou ${ret.toInt32()}`);
      }
    });
    log('NETHTP', `hook engine @ ${fnEngine}`);
  } catch(e) { log('NETHTP', `engine hook err: ${e.message}`); }

  // Observar marshaler — quando o payload é montado
  try {
    const fnMarshal = base.add(NETHTP_OFF.FUN_0033acfc);
    Interceptor.attach(fnMarshal, {
      onEnter(args) {
        log('NETHTP', `marshal chamado — arg0=${args[0]}`);
      },
      onLeave(ret) {
        log('NETHTP', `marshal retornou ${ret.toInt32()}`);
      }
    });
    log('NETHTP', `hook marshal @ ${fnMarshal}`);
  } catch(e) { log('NETHTP', `marshal hook err: ${e.message}`); }
}

// ─── Observação de syscalls suspeitas ────────────────────────────────────────

function observeSyscalls() {
  // Observar open/openat para ver quais arquivos são lidos
  try {
    const libc = Process.getModuleByName('libc.so');
    const openat = libc.getExportByName('openat');
    Interceptor.attach(openat, {
      onEnter(args) {
        try {
          const path = args[1].readCString();
          if (path && (path.includes('/proc') || path.includes('maps') || path.includes('status'))) {
            log('SYSCALL', `openat("${path}") — LR=${this.returnAddress}`);
          }
        } catch(_) {}
      }
    });
    log('SYSCALL', `hook openat @ ${openat}`);
  } catch(e) { log('SYSCALL', `openat hook err: ${e.message}`); }
}

// ─── Mapeamento de threads ────────────────────────────────────────────────────

function mapThreads() {
  log('THR', '=== Threads do processo ===');
  try {
    Process.enumerateThreads().forEach(t => {
      log('THR', `  tid=${t.id}  state=${t.state}  pc=${t.context ? t.context.pc : '?'}`);
    });
  } catch(e) { log('THR', `err: ${e.message}`); }
}

// ─── Análise de ranges de memória ────────────────────────────────────────────

function mapMemoryRanges() {
  log('MEM', '=== Ranges de memória executáveis ===');
  Process.enumerateRanges('r-x').forEach(r => {
    const name = r.file ? r.file.path.split('/').pop() : '(anon)';
    log('MEM', `  ${r.base}–${r.base.add(r.size)}  ${name}`);
  });
}

// ─── Execução principal ───────────────────────────────────────────────────────

function main() {
  log('INIT', `Iniciando exploração de ${TARGET_PKG}`);
  log('INIT', `PID=${Process.id}  Arch=${Process.arch}  Platform=${Process.platform}`);

  // Aguardar libs nativas carregarem
  setTimeout(() => {
    mapModules();
    mapMemoryRanges();
    mapThreads();

    mapExports(NESEC_NAME);
    mapExports(NETHTP_NAME);
    mapImports(NESEC_NAME);

    observeNesec();
    observeNetHTProtect();
    observeSyscalls();

    log('INIT', 'Exploração ativa — observando por até 55s...');
  }, 3000);

  // Snapshot final antes do processo encerrar
  setTimeout(() => {
    log('FINAL', '=== Snapshot final de threads ===');
    mapThreads();
    log('FINAL', 'Exploração concluída.');
  }, 55000);
}

main();