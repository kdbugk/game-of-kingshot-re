/**
 * explorer_discover.js — Descoberta automática de funções por padrões
 *
 * Busca padrões de bytes e strings conhecidas nas libs carregadas.
 * Técnica de análise estática: identificar funções pela sua assinatura
 * de código ou pelas constantes que usam internamente.
 *
 * Apenas leitura de memória. Sem modificação.
 *
 * Uso:
 *   frida -U -f com.run.tower.defense -l explorer_discover.js --no-pause
 *
 * O resultado é impresso como CSV ao final.
 */

'use strict';

const GHIDRA_BASE = 0x100000;

function log(tag, msg) { console.log(`[${tag}] ${msg}`); }

// ─── Padrões de busca ─────────────────────────────────────────────────────────
//
// Cada padrão tem:
//   name        — nome sugestivo da função
//   description — o que ela provavelmente faz
//   type        — 'bytes' | 'string' | 'uint32'
//   pattern     — o padrão em si
//   libs        — lista de libs onde buscar (null = todas)
//   offset      — ajuste do endereço encontrado para chegar ao início da função
//                 ex: se o padrão está 0x10 bytes dentro da função, offset=-0x10

const PATTERNS = [

  // ── Constantes do algoritmo MD5 ──────────────────────────────────────────
  // A primeira constante do MD5 round 1 é 0xd76aa478
  // Em ARM64 little-endian: 78 a4 6a d7
  {
    name:        'md5_round1_start',
    description: 'Início do round 1 do MD5 — constante 0xd76aa478. Identifica implementação manual de MD5.',
    type:        'bytes',
    pattern:     '78 a4 6a d7',
    libs:        ['libNetHTProtect.so'],
    offset:      0,
  },

  // Segunda constante MD5 round 1: 0xe8c7b756 → 56 b7 c7 e8
  {
    name:        'md5_round1_k2',
    description: 'Constante K[1] do MD5 (0xe8c7b756). Confirma presença de MD5 inline.',
    type:        'bytes',
    pattern:     '56 b7 c7 e8',
    libs:        ['libNetHTProtect.so'],
    offset:      0,
  },

  // ── Strings de /proc lidas pelas libs de segurança ───────────────────────
  {
    name:        'str_proc_self_status',
    description: 'String "/proc/self/status" — lib lê esta entrada para checar TracerPid.',
    type:        'string',
    pattern:     '/proc/self/status',
    libs:        ['libnesec.so', 'libNetHTProtect.so'],
    offset:      0,
  },
  {
    name:        'str_proc_self_maps',
    description: 'String "/proc/self/maps" — lib escaneia mapeamentos de memória.',
    type:        'string',
    pattern:     '/proc/self/maps',
    libs:        ['libnesec.so', 'libNetHTProtect.so'],
    offset:      0,
  },
  {
    name:        'str_tracerpid',
    description: 'String "TracerPid" — campo específico lido de /proc/status.',
    type:        'string',
    pattern:     'TracerPid',
    libs:        ['libnesec.so'],
    offset:      0,
  },
  {
    name:        'str_frida_agent',
    description: 'String "frida-agent" — lib busca esta string nos mapeamentos de memória.',
    type:        'string',
    pattern:     'frida-agent',
    libs:        ['libnesec.so', 'libNetHTProtect.so'],
    offset:      0,
  },

  // ── Strings de identificação de ambiente ─────────────────────────────────
  {
    name:        'str_android_version',
    description: 'String de versão Android lida para fingerprint do dispositivo.',
    type:        'string',
    pattern:     'ro.build.version.sdk',
    libs:        ['libNetHTProtect.so', 'libnesec.so'],
    offset:      0,
  },
  {
    name:        'str_proc_net_tcp',
    description: 'String "/proc/net/tcp" — lib inspeciona conexões de rede ativas.',
    type:        'string',
    pattern:     '/proc/net/tcp',
    libs:        ['libnesec.so', 'libNetHTProtect.so'],
    offset:      0,
  },

  // ── Padrão de prólogo de função ARM64 ────────────────────────────────────
  // stp x29, x30, [sp, #-N]! é o prólogo padrão de função ARM64
  // bytes: fd 7b ?? d1  (stp x29, x30, [sp, #-N]!)
  // Útil para confirmar início de função após encontrar uma constante próxima
  {
    name:        'arm64_function_prolog',
    description: 'Prólogo de função ARM64: stp x29, x30, [sp, #-N]!. Indica início de função.',
    type:        'bytes',
    pattern:     'fd 7b ?? d1',
    libs:        ['libnesec.so'],
    offset:      0,
  },

  // ── Instrução RET ARM64 ──────────────────────────────────────────────────
  // c0 03 5f d6 = RET
  // Útil para encontrar funções curtas (retorno imediato)
  {
    name:        'arm64_ret',
    description: 'Instrução RET (c0 03 5f d6) em ARM64. Fim de função.',
    type:        'bytes',
    pattern:     'c0 03 5f d6',
    libs:        null,  // não usar — muitos resultados
    offset:      0,
    skip:        true,  // marcado para não executar por padrão (muito ruído)
  },

  // ── Strings de libs de hooking conhecidas ────────────────────────────────
  {
    name:        'str_xhook',
    description: 'String "xhook" — identifica a presença do SDK de PLT hooking da Tencent.',
    type:        'string',
    pattern:     'xhook',
    libs:        null,
    offset:      0,
  },
  {
    name:        'str_substrate',
    description: 'String "substrate" — identifica presença de Cydia Substrate/MSHookFunction.',
    type:        'string',
    pattern:     'substrate',
    libs:        null,
    offset:      0,
  },

  // ── Strings de erros que revelam estrutura interna ───────────────────────
  {
    name:        'str_error_init',
    description: 'Mensagem de erro de inicialização — revela ponto de falha da lib.',
    type:        'string',
    pattern:     'init failed',
    libs:        ['libnesec.so', 'libNetHTProtect.so'],
    offset:      0,
  },
];

// ─── Busca de padrão de bytes com wildcard (??) ───────────────────────────────

function searchBytes(mod, patternStr) {
  const results = [];
  try {
    const found = Memory.scanSync(mod.base, mod.size, patternStr);
    for (const match of found) {
      results.push(match.address);
    }
  } catch(e) {
    // região não legível
  }
  return results;
}

// ─── Busca de string UTF-8 ────────────────────────────────────────────────────

function searchString(mod, str) {
  const results = [];
  try {
    // Converter string para padrão de bytes hex
    const bytes = [];
    for (let i = 0; i < str.length; i++) {
      bytes.push(str.charCodeAt(i).toString(16).padStart(2, '0'));
    }
    const pattern = bytes.join(' ');
    const found = Memory.scanSync(mod.base, mod.size, pattern);
    for (const match of found) {
      results.push(match.address);
    }
  } catch(e) {}
  return results;
}

// ─── Resolver endereço para Ghidra ───────────────────────────────────────────

function toGhidra(addr, modBase) {
  const a = BigInt(addr.toString());
  const b = BigInt(modBase.toString());
  const gb = BigInt(GHIDRA_BASE);
  return '0x' + (gb + (a - b)).toString(16);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

function main() {
  log('INIT', 'explorer_discover.js — descoberta automática por padrões');

  setTimeout(() => {
    const discoveries = [];

    for (const pat of PATTERNS) {
      if (pat.skip) continue;

      // Determinar quais módulos escanear
      let modsToScan = [];
      if (pat.libs) {
        for (const name of pat.libs) {
          try { modsToScan.push(Process.getModuleByName(name)); } catch(_) {}
        }
      } else {
        // Escanear só libs do jogo (evitar falsos positivos no sistema)
        const gameLibs = ['libnesec.so', 'libNetHTProtect.so', 'libil2cpp.so',
                          'libunity.so', 'libsigner.so', 'libmain.so'];
        for (const name of gameLibs) {
          try { modsToScan.push(Process.getModuleByName(name)); } catch(_) {}
        }
      }

      for (const mod of modsToScan) {
        let addrs = [];

        if (pat.type === 'bytes') {
          addrs = searchBytes(mod, pat.pattern);
        } else if (pat.type === 'string') {
          addrs = searchString(mod, pat.pattern);
        }

        for (const addr of addrs) {
          const adjusted = addr.add(pat.offset || 0);
          const ghidra   = toGhidra(adjusted, mod.base);
          const offset   = '0x' + (BigInt(adjusted.toString()) - BigInt(mod.base.toString())).toString(16);

          discoveries.push({
            lib:         mod.name,
            name:        pat.name,
            type:        pat.type,
            pattern:     pat.pattern,
            offset:      offset,
            runtime:     adjusted.toString(),
            ghidra:      ghidra,
            description: pat.description,
          });

          log('FOUND', `${mod.name} | ${pat.name} | offset=${offset} | ghidra=${ghidra}`);
        }

        if (addrs.length === 0) {
          log('MISS', `${mod.name} | ${pat.name} | padrão não encontrado`);
        }
      }
    }

    // ── Imprimir CSV ──────────────────────────────────────────────────────
    log('CSV', '=== CSV de descobertas (copie o bloco abaixo) ===');
    log('CSV', '--- INICIO ---');

    const header = ['lib', 'name', 'type', 'pattern', 'offset', 'runtime_addr', 'ghidra_addr', 'description'].join(',');
    console.log(header);

    for (const d of discoveries) {
      const row = [
        d.lib,
        d.name,
        d.type,
        '"' + d.pattern + '"',
        d.offset,
        d.runtime,
        d.ghidra,
        '"' + d.description.replace(/"/g, "'") + '"',
      ].join(',');
      console.log(row);
    }

    log('CSV', '--- FIM ---');
    log('DONE', `Total de descobertas: ${discoveries.length}`);

  }, 3000);
}

main();
