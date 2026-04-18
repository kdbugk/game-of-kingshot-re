/**
 * addr_calc.js — Calculadora de endereços runtime ↔ Ghidra
 *
 * Converte endereços entre o que você vê no Frida/log e o que
 * precisa pesquisar no Ghidra, e vice-versa.
 *
 * Uso standalone (Node.js, sem Frida):
 *   node addr_calc.js
 *
 * Ou como módulo Frida (imprime conversões automáticas das libs conhecidas):
 *   frida -U -f com.run.tower.defense -l addr_calc.js --no-pause
 *
 * ── Fórmulas ──────────────────────────────────────────────────────────────────
 *
 *   offset       = ghidra_addr  - ghidra_base
 *   runtime_addr = runtime_base + offset
 *   ghidra_addr  = ghidra_base  + (runtime_addr - runtime_base)
 *
 * ── Exemplos ──────────────────────────────────────────────────────────────────
 *
 *   Você viu no log:   libnesec.so base=0x716ff83000
 *   Ghidra mostra:     FUN_003811bc (base 0x100000)
 *   offset = 0x003811bc - 0x100000 = 0x2811bc
 *   runtime = 0x716ff83000 + 0x2811bc = 0x71701e4bc  ← hook aqui no Frida
 *
 *   Você viu no log:   PC = 0x716ffdc8f4  (libnesec.so base=0x716ff83000)
 *   ghidra_addr = 0x100000 + (0x716ffdc8f4 - 0x716ff83000) = 0x1598f4  ← pesquise no Ghidra
 */

'use strict';

const GHIDRA_BASE_DEFAULT = 0x100000;

// ─── Funções de conversão ─────────────────────────────────────────────────────

/**
 * runtime_addr → ghidra_addr
 * @param {BigInt|number|string} runtimeAddr  - endereço visto no Frida/log
 * @param {BigInt|number|string} runtimeBase  - base do módulo no dispositivo
 * @param {BigInt|number|string} ghidraBase   - base do Ghidra (padrão 0x100000)
 */
function toGhidra(runtimeAddr, runtimeBase, ghidraBase = GHIDRA_BASE_DEFAULT) {
  const addr = BigInt(runtimeAddr);
  const base = BigInt(runtimeBase);
  const gb   = BigInt(ghidraBase);
  const offset = addr - base;
  return {
    offset:     '0x' + offset.toString(16),
    ghidraAddr: '0x' + (gb + offset).toString(16),
  };
}

/**
 * ghidra_addr → runtime_addr
 * @param {BigInt|number|string} ghidraAddr   - endereço no Ghidra
 * @param {BigInt|number|string} runtimeBase  - base do módulo no dispositivo
 * @param {BigInt|number|string} ghidraBase   - base do Ghidra (padrão 0x100000)
 */
function toRuntime(ghidraAddr, runtimeBase, ghidraBase = GHIDRA_BASE_DEFAULT) {
  const gAddr  = BigInt(ghidraAddr);
  const base   = BigInt(runtimeBase);
  const gb     = BigInt(ghidraBase);
  const offset = gAddr - gb;
  return {
    offset:      '0x' + offset.toString(16),
    runtimeAddr: '0x' + (base + offset).toString(16),
  };
}

// ─── Modo Frida — conversão automática das libs conhecidas ───────────────────

function runAsFrida() {
  console.log('[CALC] addr_calc.js — Calculadora de endereços runtime ↔ Ghidra');
  console.log('[CALC] Ghidra base padrão: 0x' + GHIDRA_BASE_DEFAULT.toString(16));

  setTimeout(() => {
    const libs = [
      'libnesec.so',
      'libNetHTProtect.so',
      'libil2cpp.so',
      'libunity.so',
      'libsigner.so',
      'libmain.so',
    ];

    console.log('\n[CALC] === Bases de runtime detectadas ===');
    for (const name of libs) {
      try {
        const mod = Process.getModuleByName(name);
        const base = mod.base.toString();
        // Mostrar exemplos de conversão para o primeiro endereço de cada lib
        console.log(`\n[CALC] ${name}`);
        console.log(`[CALC]   runtime base = ${base}`);
        console.log(`[CALC]   ghidra  base = 0x${GHIDRA_BASE_DEFAULT.toString(16)}`);
        console.log(`[CALC]   fórmula runtime→ghidra: ghidra_addr = 0x${GHIDRA_BASE_DEFAULT.toString(16)} + (runtime_addr - ${base})`);
        console.log(`[CALC]   fórmula ghidra→runtime: runtime_addr = ${base} + (ghidra_addr - 0x${GHIDRA_BASE_DEFAULT.toString(16)})`);
      } catch(_) {
        console.log(`[CALC] ${name}: não encontrado`);
      }
    }

    // Tabela de conversão das funções conhecidas
    console.log('\n[CALC] === Conversão das funções mapeadas ===');
    console.log('[CALC] ' + [
      'lib'.padEnd(22),
      'ghidra_addr'.padEnd(14),
      'offset'.padEnd(12),
      'runtime_addr',
    ].join('  '));
    console.log('[CALC] ' + '-'.repeat(75));

    const FUNCS = [
      { lib: 'libnesec.so',        ghidra: 0x1698f4,  name: 'nesec_coleta_dados' },
      { lib: 'libnesec.so',        ghidra: 0x10f54c,  name: 'nesec_nivel_deteccao' },
      { lib: 'libnesec.so',        ghidra: 0x2811bc,  name: 'nesec_singleton_getter' },
      { lib: 'libnesec.so',        ghidra: 0x3b6168,  name: 'nesec_acao_kill' },
      { lib: 'libNetHTProtect.so', ghidra: 0x33d5a0,  name: 'nethtp_engine_central' },
      { lib: 'libNetHTProtect.so', ghidra: 0x33acfc,  name: 'nethtp_marshal_payload' },
      { lib: 'libNetHTProtect.so', ghidra: 0x19ed9c,  name: 'nethtp_pipeline_coleta' },
      { lib: 'libNetHTProtect.so', ghidra: 0x3595b0,  name: 'nethtp_config_getter' },
    ];

    for (const fn of FUNCS) {
      try {
        const mod    = Process.getModuleByName(fn.lib);
        const base   = BigInt(mod.base.toString());
        const gb     = BigInt(GHIDRA_BASE_DEFAULT);
        const gAddr  = BigInt(fn.ghidra);
        const offset = gAddr - gb;
        const rt     = base + offset;

        console.log('[CALC] ' + [
          fn.lib.padEnd(22),
          ('0x' + gAddr.toString(16)).padEnd(14),
          ('0x' + offset.toString(16)).padEnd(12),
          '0x' + rt.toString(16),
        ].join('  ') + `  ← ${fn.name}`);
      } catch(_) {}
    }

    // ── Exemplo interativo: converter o PC misterioso do output anterior ─────
    console.log('\n[CALC] === Exemplo: resolver PC desconhecido ===');
    try {
      const nesec = Process.getModuleByName('libnesec.so');
      // PC exemplo: 0x716ffdc8f4 (FUN_698f4 que apareceu no hook)
      const examplePC = BigInt(nesec.base.toString()) + BigInt(0x598f4);
      const res = toGhidra(examplePC, nesec.base.toString());
      console.log(`[CALC] PC runtime  = 0x${examplePC.toString(16)}`);
      console.log(`[CALC] → offset    = ${res.offset}`);
      console.log(`[CALC] → ghidra    = ${res.ghidraAddr}  (pesquise isso no Ghidra)`);
    } catch(_) {}

    console.log('\n[CALC] Conversão concluída.');
  }, 3000);
}

// ─── Modo Node.js — calculadora interativa no terminal ───────────────────────

function runAsNode() {
  const readline = require('readline');
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

  console.log('');
  console.log('╔══════════════════════════════════════════════════════╗');
  console.log('║   Calculadora de Endereços  runtime ↔ Ghidra         ║');
  console.log('╠══════════════════════════════════════════════════════╣');
  console.log('║  Ghidra base padrão: 0x100000                        ║');
  console.log('║                                                       ║');
  console.log('║  Comandos:                                            ║');
  console.log('║    r2g  <runtime_addr> <runtime_base>                 ║');
  console.log('║         runtime → ghidra                              ║');
  console.log('║                                                       ║');
  console.log('║    g2r  <ghidra_addr> <runtime_base>                  ║');
  console.log('║         ghidra → runtime                              ║');
  console.log('║                                                       ║');
  console.log('║    off  <ghidra_addr>                                 ║');
  console.log('║         calcula offset puro (ghidra_addr - 0x100000) ║');
  console.log('║                                                       ║');
  console.log('║    q    sair                                          ║');
  console.log('╚══════════════════════════════════════════════════════╝');
  console.log('');

  const prompt = () => rl.question('calc> ', (line) => {
    const parts = line.trim().split(/\s+/);
    const cmd   = parts[0];

    try {
      if (cmd === 'q' || cmd === 'exit') {
        rl.close();
        return;
      }

      if (cmd === 'r2g') {
        if (parts.length < 3) { console.log('uso: r2g <runtime_addr> <runtime_base>'); }
        else {
          const res = toGhidra(parts[1], parts[2]);
          console.log(`  offset      = ${res.offset}`);
          console.log(`  ghidra_addr = ${res.ghidraAddr}  ← pesquise no Ghidra`);
        }
      } else if (cmd === 'g2r') {
        if (parts.length < 3) { console.log('uso: g2r <ghidra_addr> <runtime_base>'); }
        else {
          const res = toRuntime(parts[1], parts[2]);
          console.log(`  offset       = ${res.offset}`);
          console.log(`  runtime_addr = ${res.runtimeAddr}  ← use no Frida`);
        }
      } else if (cmd === 'off') {
        if (parts.length < 2) { console.log('uso: off <ghidra_addr>'); }
        else {
          const offset = BigInt(parts[1]) - BigInt(GHIDRA_BASE_DEFAULT);
          console.log(`  offset = 0x${offset.toString(16)}`);
        }
      } else if (cmd === '') {
        // linha vazia, ok
      } else {
        console.log(`Comando desconhecido: ${cmd}`);
      }
    } catch(e) {
      console.log(`Erro: ${e.message} — verifique se os endereços estão em hex (0x...)`);
    }

    prompt();
  });

  prompt();
}

// ─── Detecção de ambiente ─────────────────────────────────────────────────────

if (typeof Process !== 'undefined' && typeof Interceptor !== 'undefined') {
  // Rodando dentro do Frida
  runAsFrida();
} else {
  // Rodando como Node.js standalone
  runAsNode();
}
