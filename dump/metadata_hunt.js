'use strict';
/**
 * metadata_hunt.js
 *
 * Localiza global-metadata.dat descriptografado em memória.
 *
 * CORREÇÃO v2: hooks openat/open64/read só são instalados APÓS libil2cpp.so
 * carregar. Instalar esses hooks antes disso causava deadlock de mutex entre
 * o lock interno do linker e o lock do Frida interceptor, travando a thread
 * main em NativeLoader.load (ANR observado na sessão anterior).
 *
 * Estratégia:
 *  1. Polling aguarda libil2cpp.so aparecer no mapa de módulos
 *  2. SÓ ENTÃO instala hooks em openat/open64/read
 *  3. Também hooka il2cpp_init imediatamente após detectar a lib
 *  4. Scan em múltiplos momentos: EOF do read(), il2cpp_init enter/leave
 *  5. Scan periódico como fallback
 */

const TARGET_FILE   = 'global-metadata.dat';
const MAGIC_PATTERN = 'af 1b b1 fa';

// Estado global
const metadataFds    = new Set();
let   captureAllMmaps = false; // true durante open64 para capturar mmap sem esperar onLeave
let   totalRead      = 0;
let   dumpStarted    = false;
let   scanCount      = 0;
let   hooksInstalled = false;
let   htpxAddr       = null;  // endereço mmap'd do HTPX após FUN_01944070 LEAVE
let   htpxSize       = 0;     // tamanho da região HTPX

// ─────────────────────────────────────────────
// Utilidades
// ─────────────────────────────────────────────

function hexAt(addr, n) {
  try {
    return Array.from(new Uint8Array(addr.readByteArray(n)))
      .map(x => x.toString(16).padStart(2, '0')).join(' ');
  } catch (_) { return '(??)'; }
}

function sizeStr(bytes) {
  if (bytes >= 1024 * 1024) return (bytes / 1024 / 1024).toFixed(2) + 'MB';
  return (bytes / 1024).toFixed(1) + 'KB';
}

// Captura e loga o backtrace com offsets relativos aos módulos
function logBacktrace(ctx, label) {
  try {
    const frames = Thread.backtrace(ctx, Backtracer.ACCURATE);
    console.log('[BT] ' + label + ' (' + frames.length + ' frames):');
    frames.slice(0, 12).forEach((addr, i) => {
      let info = addr.toString();
      const mod = Process.findModuleByAddress(addr);
      if (mod) {
        const off = addr.sub(mod.base);
        info = mod.name + '+0x' + off.toString(16);
      }
      console.log('  #' + i.toString().padStart(2, '0') + '  ' + addr + '  ' + info);
    });
  } catch (e) {
    console.log('[BT] erro: ' + e.message);
  }
}

// ─────────────────────────────────────────────
// Catálogo de memória anônima após il2cpp_init
// ─────────────────────────────────────────────

function dumpAnonState() {
  console.log('\n[AnonState] Ranges anônimos > 512KB após il2cpp_init:');
  const perms = ['rw-', 'r--', 'rwx', 'r-x', '---'];
  const seen  = new Set();
  const interesting = [];

  for (const perm of perms) {
    let ranges;
    try { ranges = Process.enumerateRanges(perm); }
    catch (_) { continue; }
    for (const r of ranges) {
      if (r.file) continue;
      if (r.size < 512 * 1024) continue;
      const key = r.base.toString();
      if (seen.has(key)) continue;
      seen.add(key);
      let preview = '(inacessível)';
      try { preview = hexAt(r.base, 8); } catch (_) {}
      console.log('  ' + r.base + '  ' + sizeStr(r.size).padStart(9) +
                  '  ' + perm + '  [' + preview + ']');
      // Marcar como interessante: começa com "037\0" OU tamanho similar ao HTPX (9-14MB)
      if (perm !== '---' &&
          (preview.startsWith('30 33 37') ||
           (r.size >= 9*1024*1024 && r.size <= 14*1024*1024))) {
        interesting.push(r);
      }
    }
  }
  console.log('[AnonState] fim\n');

  // Inspecionar regiões interessantes com mais profundidade
  if (interesting.length > 0) {
    console.log('[AnonState] Inspecionando ' + interesting.length + ' região(ões) de interesse:');
    for (const r of interesting) {
      console.log('\n  >>> ' + r.base + '  ' + sizeStr(r.size));
      // Primeiros 64 bytes
      try {
        for (let off = 0; off < 64; off += 16) {
          console.log('  ' + hexAt(r.base.add(off), 16));
        }
      } catch (_) {}
      // Buscar magic IL2CPP nesta região
      try {
        const hits = Memory.scanSync(r.base, Math.min(r.size, 32 * 1024 * 1024), 'af 1b b1 fa');
        if (hits.length > 0) {
          console.log('  [!!!] IL2CPP magic: ' + hits.length + ' hit(s)!');
          hits.forEach(h => {
            const ver = h.address.add(4).readS32();
            console.log('  HIT @ ' + h.address + '  ver=' + ver + '  hex: ' + hexAt(h.address, 24));
          });
        } else {
          console.log('  (sem IL2CPP magic)');
        }
      } catch (e) { console.log('  scan erro: ' + e.message); }
    }
  }
}

// ─────────────────────────────────────────────
// Scan de memória
// ─────────────────────────────────────────────

function scanMemory(label) {
  const n = ++scanCount;
  console.log('\n[SCAN #' + n + '] ' + label);

  // Todas as permissões que permitem leitura
  const perms = ['rw-', 'rwx', 'r--', 'r-x'];
  const matches = [];

  for (const perm of perms) {
    let ranges;
    try { ranges = Process.enumerateRanges(perm); }
    catch (_) { continue; }

    for (const r of ranges) {
      // Pular regiões mínimas (< 64KB) — metadata terá dezenas de MB
      if (r.size < 64 * 1024) continue;

      // Pular libs grandes de sistema que sabemos o conteúdo
      if (r.file) {
        const p = r.file.path;
        if (p.includes('libunity') || p.includes('/system/') ||
            p.includes('boot.art') || p.includes('.apk') ||
            p.includes('libart') || p.includes('libdvm'))
          continue;
      }

      let hits;
      try { hits = Memory.scanSync(r.base, r.size, MAGIC_PATTERN); }
      catch (_) { continue; }

      for (const hit of hits) {
        let ver = -1;
        try { ver = hit.address.add(4).readS32(); } catch (_) {}
        matches.push({ addr: hit.address, ver, region: r, perm });
        console.log('  [HIT] ' + hit.address +
                    '  perm=' + perm +
                    '  ver=' + ver +
                    '  regionSize=' + sizeStr(r.size) +
                    (r.file ? '  (' + r.file.path.split('/').pop() + ')' : '  (anon)'));
        console.log('        hex: ' + hexAt(hit.address, 24));
      }
    }
  }

  if (matches.length === 0) {
    console.log('  [--] Nenhum match encontrado');
    return;
  }

  console.log('  [+] Total: ' + matches.length + ' match(es)');

  // Selecionar melhor candidato para dump
  // Prioridade: ver 24-29 > ver > 0 > ver = 0
  const best =
    matches.find(m => m.ver >= 24 && m.ver <= 29) ||
    matches.find(m => m.ver > 0) ||
    matches[0];

  if (best && !dumpStarted) {
    dumpStarted = true;
    dumpCandidate(best);
  }
}

// ─────────────────────────────────────────────
// Dump via send()
// ─────────────────────────────────────────────

function dumpCandidate(match) {
  const addr   = match.addr;
  const region = match.region;

  // Dump começa no match (início do metadata) até o fim da região
  const startOff = addr.sub(region.base).toInt32();
  const total    = region.size - startOff;

  console.log('\n[DUMP] Candidato: ' + addr +
              ' | perm=' + match.perm +
              ' | ver=' + match.ver +
              ' | tamanho estimado=' + sizeStr(total));

  send({ type: 'dump_start', addr: addr.toString(), total_bytes: total });

  const CHUNK = 512 * 1024; // 512KB por chunk
  let offset = 0;

  function nextChunk() {
    if (offset >= total) {
      send({ type: 'dump_done', total_bytes: offset });
      console.log('[DUMP] Concluído: ' + sizeStr(offset));
      return;
    }
    const sz = Math.min(CHUNK, total - offset);
    try {
      const data = addr.add(offset).readByteArray(sz);
      send({ type: 'chunk', offset }, data);
      offset += sz;
    } catch (e) {
      console.log('[DUMP] Erro offset=' + offset.toString(16) + ': ' + e.message);
      offset += sz; // pular chunk problemático
    }
    setTimeout(nextChunk, 0); // yieldar para não travar o runtime
  }

  nextChunk();
}

// ─────────────────────────────────────────────
// Hooks principais — só instalados após libil2cpp carregar
// ─────────────────────────────────────────────

function installAllHooks() {
  if (hooksInstalled) return;
  hooksInstalled = true;

  const libc = Process.getModuleByName('libc.so');
  console.log('[+] Instalando hooks (libil2cpp já carregada)');

  // openat(dirfd, path, flags, ...)
  try {
    Interceptor.attach(libc.getExportByName('openat'), {
      onEnter(args) {
        try {
          const path = args[1].readCString();
          if (path && path.includes(TARGET_FILE)) {
            this.hit = true;
            console.log('[OPEN] openat: ' + path);
            logBacktrace(this.context, 'openat caller');
          }
        } catch (_) {}
      },
      onLeave(retval) {
        if (this.hit) {
          metadataFds.add(retval.toInt32());
          console.log('[OPEN] openat fd=' + retval.toInt32());
        }
      }
    });
    console.log('[+] hook openat ok');
  } catch (e) { console.log('[!] openat: ' + e.message); }

  // open64(path, flags, ...)
  try {
    Interceptor.attach(libc.getExportByName('open64'), {
      onEnter(args) {
        try {
          const path = args[0].readCString();
          if (path && path.includes(TARGET_FILE)) {
            this.hit = true;
            captureAllMmaps = true; // ativa captura de mmaps AGORA (antes do fd existir)
            console.log('[OPEN] open64: ' + path);
            logBacktrace(this.context, 'open64 caller');
          }
        } catch (_) {}
      },
      onLeave(retval) {
        if (this.hit) {
          const fd = retval.toInt32();
          metadataFds.add(fd);
          captureAllMmaps = false;
          console.log('[OPEN] open64 fd=' + fd);
        }
      }
    });
    console.log('[+] hook open64 ok');
  } catch (e) { console.log('[!] open64: ' + e.message); }

  // read(fd, buf, count)
  try {
    Interceptor.attach(libc.getExportByName('read'), {
      onEnter(args) {
        const fd = args[0].toInt32();
        if (!metadataFds.has(fd)) return;
        this.isTarget = true;
        this.buf = args[1];
        this.count = args[2].toInt32();
      },
      onLeave(retval) {
        if (!this.isTarget) return;
        const n = retval.toInt32();
        if (n > 0) {
          totalRead += n;

          // Primeiros 3 chunks: logar bytes brutos para ver o formato HTPX
          if (totalRead <= 3 * 1024) {
            const preview = hexAt(this.buf, Math.min(n, 32));
            console.log('[READ] chunk #' + Math.ceil(totalRead / n) +
                        '  n=' + n + '  buf=' + this.buf + '  hex=' + preview);
            if (totalRead === n) {
              // Primeiro chunk — capturar backtrace para saber o caller
              logBacktrace(this.context, 'read caller (1º chunk)');
            }
          }

          // Log de progresso a cada 2MB
          if (totalRead % (2 * 1024 * 1024) < this.count)
            console.log('[READ] progresso: ' + sizeStr(totalRead));

        } else if (n === 0) {
          // EOF — a leitura terminou
          console.log('[READ] EOF — total lido: ' + sizeStr(totalRead));
          scanMemory('pós-EOF imediato');
          setTimeout(() => scanMemory('pós-EOF +200ms'), 200);
          setTimeout(() => scanMemory('pós-EOF +1s'),    1000);
          setTimeout(() => scanMemory('pós-EOF +5s'),    5000);
          setTimeout(() => scanMemory('pós-EOF +15s'),  15000);
        }
      }
    });
    console.log('[+] hook read ok');
  } catch (e) { console.log('[!] read: ' + e.message); }

  // pread64(fd, buf, count, offset) — Unity usa pread64 para acesso posicional
  try {
    Interceptor.attach(libc.getExportByName('pread64'), {
      onEnter(args) {
        const fd = args[0].toInt32();
        if (!metadataFds.has(fd)) return;
        this.isTarget = true;
        this.buf    = args[1];
        this.count  = args[2].toInt32();
        this.offset = parseInt(args[3].toString());
        console.log('[PREAD64] fd=' + fd + ' count=' + sizeStr(this.count) + ' offset=' + this.offset);
      },
      onLeave(retval) {
        if (!this.isTarget) return;
        const n = retval.toInt32();
        if (n > 0) {
          totalRead += n;
          const preview = hexAt(this.buf, Math.min(n, 32));
          console.log('[PREAD64] leu ' + sizeStr(n) + ' total=' + sizeStr(totalRead) + ' hex=' + preview);
          if (totalRead % (2 * 1024 * 1024) < this.count)
            console.log('[PREAD64] progresso: ' + sizeStr(totalRead));
        } else if (n === 0) {
          console.log('[PREAD64] EOF — total lido: ' + sizeStr(totalRead));
          setTimeout(() => scanMemory('pós-pread64 EOF +200ms'), 200);
          setTimeout(() => scanMemory('pós-pread64 EOF +1s'),    1000);
          setTimeout(() => scanMemory('pós-pread64 EOF +5s'),    5000);
        }
      }
    });
    console.log('[+] hook pread64 ok');
  } catch (e) { console.log('[!] pread64: ' + e.message); }

  // mprotect — detectar quando o HTPX é protegido (PROT_NONE) vs munmap'd
  try {
    Interceptor.attach(libc.getExportByName('mprotect'), {
      onEnter(args) {
        if (htpxAddr === null) return;
        const addr = args[0];
        const len  = parseInt(args[1].toString());
        const prot = args[2].toInt32();
        // Verificar se o endereço está dentro da região HTPX
        const htpxEnd = htpxAddr.add(htpxSize);
        if (addr.compare(htpxAddr) >= 0 && addr.compare(htpxEnd) < 0) {
          const protStr = (prot === 0 ? 'PROT_NONE' : '0x' + prot.toString(16));
          console.log('[mprotect] HTPX addr=' + addr + ' len=' + sizeStr(len) + ' prot=' + protStr);
          if (prot === 0) {
            console.log('  → PROT_NONE: região protegida (ainda mapeada, não liberada)');
          }
        }
      }
    });
    console.log('[+] hook mprotect ok');
  } catch (e) { console.log('[!] mprotect: ' + e.message); }

  // close() — remove fd do set quando fechado (evita rastrear fds reutilizados)
  try {
    Interceptor.attach(libc.getExportByName('close'), {
      onEnter(args) {
        const fd = args[0].toInt32();
        if (metadataFds.has(fd)) {
          metadataFds.delete(fd);
          console.log('[CLOSE] fd=' + fd + ' removido do tracking');
        }
      }
    });
    console.log('[+] hook close ok');
  } catch (e) { console.log('[!] close: ' + e.message); }

  // Funções internas do IL2CPP — inícios reais identificados via Ghidra (dump decriptado, base=0)
  // ATENÇÃO: offsets anteriores (0x194baa4 etc.) eram endereços de RETORNO do backtrace,
  //          não inícios de função — onLeave nunca disparava corretamente.
  const il2cpp = Process.getModuleByName('libil2cpp.so');

  // FUN_01944070 — mmap_caller
  // Retorna diretamente o endereço mapeado por mmap().
  // param_2 (args[1]) é um ponteiro que recebe o tamanho calculado (*param_2 = size).
  // Em onLeave, retval = endereço mapeado, this.sizePtr.readU64() = tamanho.
  try {
    const mmapCallerFn = il2cpp.base.add(0x1944070);
    Interceptor.attach(mmapCallerFn, {
      onEnter(args) {
        this.sizePtr = args[1]; // *args[1] será escrito com o tamanho antes do mmap
        console.log('[FUN_01944070] ENTER  arg0=' + args[0] + '  sizePtr=' + args[1]);
      },
      onLeave(retval) {
        const mappedAddr = retval;
        let mappedSize = 0;
        try { mappedSize = this.sizePtr.readU64().toNumber(); } catch (_) {}
        console.log('[FUN_01944070] LEAVE  addr=' + mappedAddr + '  size=' + sizeStr(mappedSize));

        if (mappedAddr.isNull() || mappedAddr.toInt32() === -1 || mappedSize === 0) {
          console.log('  [mmap_caller] retornou null/-1 ou size=0 — sem polling');
          return;
        }

        const preview = hexAt(mappedAddr, 32);
        console.log('  primeiros 32 bytes: ' + preview);

        // Salvar globalmente
        htpxAddr = mappedAddr;
        htpxSize = mappedSize;

        // Detectar magic IL2CPP (decriptado) ou HTPX (encriptado)
        const IL2CPP_MAGIC = 0xfab11baf; // af 1b b1 fa
        const HTPX_MAGIC   = 0x58505448; // 48 54 50 58 = "HTPX"
        let curMagic;
        try { curMagic = mappedAddr.readU32(); } catch (_) { curMagic = 0; }

        if (curMagic === IL2CPP_MAGIC) {
          console.log('  [mmap_caller] IL2CPP já decriptado! Dump imediato.');
          if (!dumpStarted) {
            dumpStarted = true;
            dumpCandidate({ addr: mappedAddr, ver: mappedAddr.add(4).readS32(),
                            region: { base: mappedAddr, size: mappedSize }, perm: 'r--' });
          }
          return;
        }

        if (curMagic === HTPX_MAGIC) {
          console.log('  [mmap_caller] HTPX detectado — copiando ' + sizeStr(mappedSize) + ' sincronamente...');
          // Copia TODOS os bytes agora (síncrono) antes que a região seja liberada/protegida
          let htpxBytes = null;
          try {
            htpxBytes = mappedAddr.readByteArray(mappedSize);
            console.log('  [mmap_caller] cópia OK — enviando como htpx_raw');
          } catch (e) {
            console.log('  [mmap_caller] erro ao ler HTPX: ' + e.message);
          }
          if (htpxBytes) {
            // Enviar em chunks (assíncrono pois já temos os bytes no heap JS)
            send({ type: 'htpx_start', size: mappedSize });
            const CHUNK = 512 * 1024;
            let off = 0;
            function sendHtpxChunk() {
              if (off >= mappedSize) {
                send({ type: 'htpx_done', size: mappedSize });
                console.log('  [HTPX] enviado: ' + sizeStr(mappedSize));
                return;
              }
              send({ type: 'htpx_chunk', offset: off }, htpxBytes.slice(off, off + CHUNK));
              off += CHUNK;
              setTimeout(sendHtpxChunk, 0);
            }
            sendHtpxChunk();
          }
        }

        // Polling: verifica se decriptação in-place acontece nos próximos 2s
        let pollCount = 0;
        const maxPolls = 20; // 20 × 100ms = 2s
        const poll = setInterval(() => {
          pollCount++;
          let cur;
          try { cur = mappedAddr.readU32(); } catch (_) {
            console.log('[HTPX-poll] região inacessível após ' + (pollCount * 100) + 'ms');
            clearInterval(poll);
            return;
          }
          if (cur === IL2CPP_MAGIC) {
            clearInterval(poll);
            console.log('[HTPX-poll] Decriptado in-place após ' + (pollCount * 100) + 'ms!');
            if (!dumpStarted) {
              dumpStarted = true;
              dumpCandidate({ addr: mappedAddr, ver: mappedAddr.add(4).readS32(),
                              region: { base: mappedAddr, size: mappedSize }, perm: 'rw-' });
            }
          }
          if (pollCount >= maxPolls) { clearInterval(poll); }
        }, 100);
      }
    });
    console.log('[+] hook FUN_01944070 (mmap_caller) @ ' + mmapCallerFn);
  } catch (e) { console.log('[!] FUN_01944070: ' + e.message); }

  // FUN_0194b9d8 (path_builder) e FUN_0192cc00 (mutex_scheduler) — apenas log de ENTER/LEAVE
  const OBSERVER_HOOKS = [
    { offset: 0x194b9d8, label: 'FUN_0194b9d8 (path_builder)' },
    { offset: 0x192cc00, label: 'FUN_0192cc00 (mutex_scheduler)' },
  ];

  for (const h of OBSERVER_HOOKS) {
    try {
      const fn = il2cpp.base.add(h.offset);
      Interceptor.attach(fn, {
        onEnter(args) {
          this.label = h.label;
          console.log('[' + h.label + '] ENTER  arg0=' + args[0] + '  arg1=' + args[1]);
        },
        onLeave(retval) {
          console.log('[' + this.label + '] LEAVE  retval=' + retval);
        }
      });
      console.log('[+] hook ' + h.label + ' @ ' + fn);
    } catch (e) {
      console.log('[!] hook ' + h.label + ': ' + e.message);
    }
  }

  // il2cpp_init — sem scans síncronos para não atrasar a thread de init
  try {
    const initFn = il2cpp.getExportByName('il2cpp_init');
    Interceptor.attach(initFn, {
      onEnter() {
        console.log('[il2cpp_init] ENTER');
      },
      onLeave() {
        console.log('[il2cpp_init] LEAVE — catalogando memória anônima...');
        setTimeout(() => {
          // Catalogar TODOS os ranges anônimos > 512KB com qualquer permissão
          dumpAnonState();
          scanMemory('il2cpp_init LEAVE');
        }, 0);
        setTimeout(() => scanMemory('il2cpp_init +1s'), 1000);
      }
    });
    console.log('[+] il2cpp_init hookado @ ' + initFn);
  } catch (e) { console.log('[!] il2cpp_init: ' + e.message); }

  // Primeiro scan assíncrono — não bloqueia a thread de load
  setTimeout(() => scanMemory('pós-load imediato'), 0);
}

// ─────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────

function main() {
  console.log('[+] metadata_hunt.js carregado — aguardando libil2cpp.so...');

  // NÃO instala nenhum hook aqui. Aguarda libil2cpp carregar via polling.
  // Isso evita o deadlock mutex linker ↔ Frida observado na sessão anterior.
  const poll = setInterval(() => {
    const il2cpp = Process.findModuleByName('libil2cpp.so');
    if (!il2cpp) return;

    clearInterval(poll);
    console.log('[+] libil2cpp.so detectada: base=' + il2cpp.base +
                ' size=' + sizeStr(il2cpp.size));
    installAllHooks();

    // Scan periódico leve — só se o HTPX-poll não encontrou nada ainda
    // Intervalo longo para não competir com a decriptação do HTPX
    let periodicN = 0;
    const periodic = setInterval(() => {
      if (dumpStarted) { clearInterval(periodic); return; }
      // Não fazer scan se HTPX-poll ainda está rodando (ele fará scans de fallback)
      if (htpxAddr !== null) return;
      scanMemory('periódico #' + (++periodicN));
      if (periodicN >= 6) clearInterval(periodic); // 6 × 10s = 60s
    }, 10000);

  }, 100);
}

main();
