/**
 * explorer_threads.js — Análise de threads do processo
 *
 * Observa a criação e estado de threads ao longo do tempo.
 * Tenta identificar a qual módulo/lib cada thread pertence
 * pelo endereço de PC comparado com os ranges de memória.
 *
 * Apenas observação. Sem modificação de memória.
 *
 * Uso:
 *   frida -U -f com.run.tower.defense -l explorer_threads.js --no-pause
 */

'use strict';

function log(tag, msg) {
  console.log(`[${tag}] ${msg}`);
}

// Resolve o módulo dono de um endereço usando os ranges de memória
function resolveModule(addr) {
  try {
    const ranges = Process.enumerateRanges('r-x');
    for (const r of ranges) {
      if (addr.compare(r.base) >= 0 && addr.compare(r.base.add(r.size)) < 0) {
        const name = r.file ? r.file.path.split('/').pop() : '(anon)';
        const offset = addr.sub(r.base);
        return `${name}+0x${offset.toString(16)}`;
      }
    }
    return `(fora dos ranges conhecidos — possível namespace isolado)`;
  } catch(_) {
    return '(erro ao resolver)';
  }
}

// Snapshot de threads atual — retorna Map de tid → {state, pc, module}
function snapshotThreads() {
  const snap = new Map();
  try {
    for (const t of Process.enumerateThreads()) {
      const pc = t.context ? ptr(t.context.pc.toString()) : null;
      snap.set(t.id, {
        state:  t.state,
        pc:     pc,
        module: pc ? resolveModule(pc) : '(sem pc)',
      });
    }
  } catch(e) {
    log('ERR', `enumerateThreads: ${e.message}`);
  }
  return snap;
}

// Formata uma entrada de thread para log
function fmtThread(tid, info) {
  return `tid=${String(tid).padEnd(7)} state=${info.state.padEnd(8)} pc=${info.pc || '?'} → ${info.module}`;
}

// Agrupa threads por módulo para resumo
function groupByModule(snap) {
  const groups = new Map();
  for (const [tid, info] of snap) {
    const key = info.module.split('+')[0]; // só o nome sem offset
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(tid);
  }
  return groups;
}

// ─── Main ────────────────────────────────────────────────────────────────────

function main() {
  log('INIT', `Thread Explorer — PID=${Process.id}`);

  // Snapshot inicial — registrar todas as threads existentes
  setTimeout(() => {
    log('SNAP', '=== Snapshot inicial (t=3s) ===');
    const snap0 = snapshotThreads();
    log('SNAP', `Total: ${snap0.size} threads`);

    // Detalhe completo
    for (const [tid, info] of snap0) {
      log('T0', fmtThread(tid, info));
    }

    // Resumo por módulo
    log('SNAP', '--- Resumo por módulo ---');
    for (const [mod, tids] of groupByModule(snap0)) {
      log('MOD0', `${mod.padEnd(50)} ${tids.length} thread(s) — tids: ${tids.slice(0,8).join(', ')}${tids.length > 8 ? '...' : ''}`);
    }

    // ── Monitoramento periódico de novas threads ──────────────────────────────
    let prevSnap = snap0;
    let tick = 0;

    const interval = setInterval(() => {
      tick++;
      const now = snapshotThreads();

      // Threads novas
      const novas = [];
      for (const [tid, info] of now) {
        if (!prevSnap.has(tid)) novas.push([tid, info]);
      }

      // Threads encerradas
      const mortas = [];
      for (const [tid, info] of prevSnap) {
        if (!now.has(tid)) mortas.push([tid, info]);
      }

      if (novas.length > 0) {
        log('NEW', `=== t=${tick * 5}s — ${novas.length} thread(s) nova(s) ===`);
        for (const [tid, info] of novas) {
          log('NEW', `  + ${fmtThread(tid, info)}`);
        }
      }

      if (mortas.length > 0) {
        log('END', `=== t=${tick * 5}s — ${mortas.length} thread(s) encerrada(s) ===`);
        for (const [tid, info] of mortas) {
          log('END', `  - ${fmtThread(tid, info)}`);
        }
      }

      // A cada 20s, imprimir resumo por módulo para ver evolução
      if (tick % 4 === 0) {
        log('SNAP', `--- Resumo por módulo (t=${tick * 5}s) total=${now.size} ---`);
        for (const [mod, tids] of groupByModule(now)) {
          log('MOD', `${mod.padEnd(50)} ${tids.length} thread(s)`);
        }
      }

      prevSnap = now;
    }, 5000); // verificar a cada 5s

    // ── Snapshot final ────────────────────────────────────────────────────────
    setTimeout(() => {
      clearInterval(interval);

      log('FINAL', '=== Snapshot final (t=55s) ===');
      const snapF = snapshotThreads();
      log('FINAL', `Total: ${snapF.size} threads`);

      // Threads que existiam no início e ainda existem
      const sobreviventes = [];
      const novas_total   = [];
      for (const [tid, info] of snapF) {
        if (snap0.has(tid)) sobreviventes.push([tid, info]);
        else novas_total.push([tid, info]);
      }

      log('FINAL', `Threads originais ainda ativas: ${sobreviventes.length}`);
      log('FINAL', `Threads criadas durante a sessão: ${novas_total.length}`);

      if (novas_total.length > 0) {
        log('FINAL', '--- Threads novas criadas durante a sessão ---');
        for (const [tid, info] of novas_total) {
          log('NEW_F', fmtThread(tid, info));
        }
      }

      // Resumo final por módulo
      log('FINAL', '--- Resumo final por módulo ---');
      for (const [mod, tids] of groupByModule(snapF)) {
        const wasInSnap0 = tids.filter(t => snap0.has(t)).length;
        const isNew      = tids.length - wasInSnap0;
        log('MODF', `${mod.padEnd(50)} total=${tids.length}  originais=${wasInSnap0}  novas=${isNew}`);
      }

      log('FINAL', 'Exploração de threads concluída.');
    }, 52000);

  }, 3000);
}

main();
