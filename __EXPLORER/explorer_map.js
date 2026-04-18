/**
 * explorer_map.js — Mapa de endereços e exportação CSV
 *
 * Coleta endereços base de todos os módulos e gera um CSV com:
 *   - nome do módulo
 *   - endereço base em runtime
 *   - offset conhecido (do Ghidra)
 *   - endereço runtime calculado
 *   - endereço Ghidra equivalente
 *   - nome sugestivo da função
 *   - descrição
 *
 * Uso:
 *   frida -U -f com.run.tower.defense -l explorer_map.js --no-pause
 *
 * O CSV é impresso no log ao final — copie e salve como .csv
 */

'use strict';

function log(tag, msg) {
  console.log(`[${tag}] ${msg}`);
}

// ─── Base do Ghidra para cada lib ─────────────────────────────────────────────
// O Ghidra carrega com base 0x100000 por padrão

const GHIDRA_BASE = {
  'libnesec.so':         0x100000,
  'libNetHTProtect.so':  0x100000,
  'libil2cpp.so':        0x100000,
  'libunity.so':         0x100000,
  'libsigner.so':        0x100000,
};

// ─── Funções conhecidas com metadados ─────────────────────────────────────────
// Formato: { lib, ghidraAddr, name, description }

const KNOWN_FUNCTIONS = [

  // ── libnesec.so ──────────────────────────────────────────────────────────
  {
    lib:         'libnesec.so',
    ghidraAddr:  0x1698f4,
    name:        'nesec_coleta_dados',
    description: 'Coleta dados do sistema (hardware, runtime, processo). Chamada periódica.',
  },
  {
    lib:         'libnesec.so',
    ghidraAddr:  0x10f54c,
    name:        'nesec_nivel_deteccao',
    description: 'Retorna nível de detecção atual. 0 = ok, >0 = anomalia detectada.',
  },
  {
    lib:         'libnesec.so',
    ghidraAddr:  0x2e3339c,
    name:        'nesec_loop_tracerpid_principal',
    description: 'Loop que verifica TracerPid de todas as threads via /proc/<tid>/status.',
  },
  {
    lib:         'libnesec.so',
    ghidraAddr:  0x2e43494,
    name:        'nesec_loop_tracerpid_redundante',
    description: 'Thread separada com lógica de TracerPid duplicada (defesa em profundidade).',
  },
  {
    lib:         'libnesec.so',
    ghidraAddr:  0x3b8f88,
    name:        'nesec_thread_extra_deteccao',
    description: 'Thread adicional de detecção — descoberta via hook de pthread_create.',
  },
  {
    lib:         'libnesec.so',
    ghidraAddr:  0x3b6168,  // 0x406168 - base 0x100000 + 0x100000 nota: offset real
    name:        'nesec_acao_kill',
    description: 'Executa ação de kill após detecção confirmada. Envia sinal ao processo.',
  },
  {
    lib:         'libnesec.so',
    ghidraAddr:  0x3b0f8,  // 0x40b0f8 - 0x100000
    name:        'nesec_deteccao_seccomp',
    description: 'Verifica presença de Seccomp/NativeBridge no processo.',
  },
  {
    lib:         'libnesec.so',
    ghidraAddr:  0x2811bc,
    name:        'nesec_singleton_getter',
    description: 'Retorna ponteiro para struct singleton de estado de detecção (0x20 bytes). Campos +0x10 e +0x14 são flags de detecção do Frida.',
  },

  // ── libNetHTProtect.so ───────────────────────────────────────────────────
  {
    lib:         'libNetHTProtect.so',
    ghidraAddr:  0x33d5a0,
    name:        'nethtp_engine_central',
    description: 'Engine principal. Valida parâmetros, escolhe pipeline (param_8 & 1). Chama FUN_0019ed9c ou FUN_001ca50c.',
  },
  {
    lib:         'libNetHTProtect.so',
    ghidraAddr:  0x33acfc,
    name:        'nethtp_marshal_payload',
    description: 'Serializa resultado do engine e entrega ao IL2CPP via vtable DAT_005a62e8.',
  },
  {
    lib:         'libNetHTProtect.so',
    ghidraAddr:  0x19ed9c,
    name:        'nethtp_pipeline_coleta',
    description: 'Pipeline principal de coleta: fingerprint do sistema, hashes MD5, dados de memória.',
  },
  {
    lib:         'libNetHTProtect.so',
    ghidraAddr:  0x1ca50c,
    name:        'nethtp_pipeline_digest',
    description: 'Pipeline alternativo — executa digest direto e calcula hash/checksum.',
  },
  {
    lib:         'libNetHTProtect.so',
    ghidraAddr:  0x2ac050,
    name:        'nethtp_encoding_varint',
    description: 'Serialização de campos em estilo varint (encoding estruturado do payload).',
  },
  {
    lib:         'libNetHTProtect.so',
    ghidraAddr:  0x3595b0,
    name:        'nethtp_config_getter',
    description: 'Retorna ponteiro para struct de configuração. Campos +0x19c, +0x19d, +0x1a4 controlam features.',
  },
  {
    lib:         'libNetHTProtect.so',
    ghidraAddr:  0x3811bc,
    name:        'nethtp_deteccao_singleton',
    description: 'Singleton getter da struct de detecção. Aloca 0x20 bytes na primeira chamada.',
  },
  {
    lib:         'libNetHTProtect.so',
    ghidraAddr:  0x35cb1c,
    name:        'nethtp_init_contexto',
    description: 'Inicializa contexto de detecção (singleton). Aloca 0x228 bytes, preenche vtable.',
  },
  {
    lib:         'libNetHTProtect.so',
    ghidraAddr:  0x396558,
    name:        'nethtp_getter_objeto_externo',
    description: 'Retorna objeto com vtable — slot +0x18 usado para coleta de dados externos.',
  },
  {
    lib:         'libNetHTProtect.so',
    ghidraAddr:  0x3e5d28,
    name:        'nethtp_getter_dados_runtime',
    description: 'Retorna struct com dados de runtime. Campo +8 usado como string de identificação.',
  },
];

// ─── Cálculo de endereços ─────────────────────────────────────────────────────

function calcAddresses(fn, runtimeBase) {
  const ghidraBase = GHIDRA_BASE[fn.lib] || 0x100000;
  const offset     = fn.ghidraAddr - ghidraBase;
  const runtimeAddr = runtimeBase + offset;
  return {
    offset:      offset,
    runtimeAddr: runtimeAddr,
    ghidraAddr:  fn.ghidraAddr,
  };
}

// ─── Geração de CSV ───────────────────────────────────────────────────────────

function generateCSV(modules) {
  const header = [
    'lib',
    'name',
    'ghidra_base',
    'ghidra_addr',
    'offset_hex',
    'runtime_base',
    'runtime_addr',
    'description',
  ].join(',');

  const rows = [];

  for (const fn of KNOWN_FUNCTIONS) {
    const mod = modules.get(fn.lib);
    if (!mod) continue;

    const addrs = calcAddresses(fn, mod.base.toUInt32 ? Number(mod.base) : parseInt(mod.base.toString()));
    const ghidraBase = GHIDRA_BASE[fn.lib] || 0x100000;

    rows.push([
      fn.lib,
      fn.name,
      '0x' + ghidraBase.toString(16),
      '0x' + fn.ghidraAddr.toString(16),
      '0x' + addrs.offset.toString(16),
      mod.base.toString(),
      '0x' + addrs.runtimeAddr.toString(16),
      '"' + fn.description.replace(/"/g, "'") + '"',
    ].join(','));
  }

  return [header, ...rows].join('\n');
}

// ─── Main ─────────────────────────────────────────────────────────────────────

function main() {
  log('INIT', 'explorer_map.js — mapeamento de endereços e geração de CSV');

  setTimeout(() => {
    // Coletar bases de todos os módulos relevantes
    const modules = new Map();
    for (const mod of Process.enumerateModules()) {
      if (GHIDRA_BASE[mod.name] !== undefined) {
        modules.set(mod.name, mod);
        log('BASE', `${mod.name.padEnd(30)} base=${mod.base}  size=${mod.size}`);
      }
    }

    // Tabela de endereços no console
    log('MAP', '=== Tabela de endereços ===');
    log('MAP', [
      'lib'.padEnd(25),
      'name'.padEnd(35),
      'offset'.padEnd(12),
      'runtime_addr'.padEnd(18),
      'ghidra_addr',
    ].join(' '));
    log('MAP', '-'.repeat(110));

    for (const fn of KNOWN_FUNCTIONS) {
      const mod = modules.get(fn.lib);
      if (!mod) {
        log('MAP', `${fn.lib.padEnd(25)} ${fn.name.padEnd(35)} (módulo não encontrado)`);
        continue;
      }

      const baseN    = parseInt(mod.base.toString());
      const addrs    = calcAddresses(fn, baseN);
      const ghidraBase = GHIDRA_BASE[fn.lib] || 0x100000;

      log('MAP', [
        fn.lib.padEnd(25),
        fn.name.padEnd(35),
        ('0x' + addrs.offset.toString(16)).padEnd(12),
        ('0x' + addrs.runtimeAddr.toString(16)).padEnd(18),
        '0x' + fn.ghidraAddr.toString(16),
      ].join(' '));
    }

    // Gerar CSV
    log('CSV', '=== CSV (copie o bloco abaixo) ===');
    log('CSV', '--- INICIO ---');
    const csv = generateCSV(modules);
    for (const line of csv.split('\n')) {
      console.log(line);
    }
    log('CSV', '--- FIM ---');

    log('DONE', 'Mapeamento concluído.');
  }, 3000);
}

main();
