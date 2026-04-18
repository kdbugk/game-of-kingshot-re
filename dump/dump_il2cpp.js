'use strict';
/**
 * dump_il2cpp.js
 *
 * Despeja libil2cpp.so decriptada da memória para análise no Ghidra.
 * A lib é decriptada pelo SDK de proteção durante o dlopen, antes do nosso
 * script rodar — o dump captura os bytes reais em execução.
 *
 * Estratégia:
 *  1. Polling aguarda libil2cpp.so aparecer (já decriptada)
 *  2. Aguarda 1s extra (decriptação assíncrona eventual)
 *  3. Dump página a página — páginas inacessíveis viram zeros (preserva estrutura ELF)
 *  4. Valida magic ELF no Python
 */

const LIB_NAME   = 'libil2cpp.so';
const CHUNK_SIZE = 512 * 1024; // 512KB por chunk
const PAGE_SIZE  = 4096;

// ─────────────────────────────────────────────
// Dump
// ─────────────────────────────────────────────

function dumpModule(mod) {
  const totalSize = mod.size;
  console.log('\n[DUMP] Iniciando dump de ' + LIB_NAME);
  console.log('[DUMP] base=' + mod.base +
              '  size=' + (totalSize / 1024 / 1024).toFixed(2) + 'MB');

  send({ type: 'dump_start', base: mod.base.toString(), size: totalSize });

  let offset     = 0;
  let errorPages = 0;

  function nextChunk() {
    if (offset >= totalSize) {
      send({ type: 'dump_done', total: totalSize, error_pages: errorPages });
      console.log('\n[DUMP] Concluído — ' + (totalSize / 1024 / 1024).toFixed(2) + 'MB' +
                  '  (' + errorPages + ' páginas inacessíveis zeradas)');
      return;
    }

    const chunkSize = Math.min(CHUNK_SIZE, totalSize - offset);
    const buf       = new Uint8Array(chunkSize);

    // Lê página a página — tolerante a páginas sem permissão de leitura
    let pageOff = 0;
    while (pageOff < chunkSize) {
      const pageBytes = Math.min(PAGE_SIZE, chunkSize - pageOff);
      try {
        const data = mod.base.add(offset + pageOff).readByteArray(pageBytes);
        buf.set(new Uint8Array(data), pageOff);
      } catch (_) {
        errorPages++; // mantém zeros (já zerado na criação do Uint8Array)
      }
      pageOff += PAGE_SIZE;
    }

    send({ type: 'chunk', offset }, buf.buffer);
    offset += chunkSize;

    // Log a cada 8MB
    if ((offset % (8 * 1024 * 1024)) < CHUNK_SIZE) {
      console.log('[DUMP] ' + (offset / 1024 / 1024).toFixed(1) + 'MB / ' +
                  (totalSize / 1024 / 1024).toFixed(1) + 'MB');
    }

    setTimeout(nextChunk, 0); // yield para não travar o runtime
  }

  nextChunk();
}

// ─────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────

function main() {
  console.log('[+] dump_il2cpp.js carregado — aguardando ' + LIB_NAME + '...');

  const poll = setInterval(() => {
    const mod = Process.findModuleByName(LIB_NAME);
    if (!mod) return;
    clearInterval(poll);

    console.log('[+] ' + LIB_NAME + ' detectada @ ' + mod.base +
                ' (' + (mod.size / 1024 / 1024).toFixed(2) + 'MB)');
    console.log('[+] Aguardando 1s para garantir decriptação assíncrona...');

    // Pequena espera — alguns SDKs decriptam em background threads logo após dlopen
    setTimeout(() => dumpModule(mod), 1000);
  }, 100);
}

main();
