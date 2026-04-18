'use strict';
/**
 * jni_tracer.js v3
 *
 * Intercepta pelo lado Java (sem hooks nativos que disparam o libnesec).
 * - Enumera classes Java com keywords do SDK NetEase
 * - Hookeia todos os métodos das classes encontradas
 * - Loga argumentos e retornos
 */

// Palavras-chave para encontrar as classes do SDK
const KEYWORDS = ['netease', 'htprotect', 'netsec', 'nesec',
                  'nethtp', 'safecomm', 'htpprotect'];

// ── Aguarda o runtime Java estar disponível ───────────────────────────────────

function waitForJava(callback, attempt) {
  attempt = attempt || 0;
  try {
    // Se Java não está definido, vai lançar ReferenceError
    const avail = Java.available;
    if (avail) {
      console.log('[Java] runtime disponível (tentativa ' + attempt + ')');
      callback();
    } else {
      setTimeout(() => waitForJava(callback, attempt + 1), 300);
    }
  } catch (_) {
    // Java global ainda não existe
    setTimeout(() => waitForJava(callback, attempt + 1), 300);
  }
}

// ── Hook de uma classe Java ───────────────────────────────────────────────────

function hookJavaClass(className) {
  try {
    const cls     = Java.use(className);
    const methods = cls.class.getDeclaredMethods();
    let   hooked  = 0;

    methods.forEach(m => {
      const mName = m.getName();
      try {
        cls[mName].overloads.forEach(overload => {
          overload.implementation = function () {
            const argStrs = Array.from(arguments).map(a => {
              if (a === null || a === undefined) return 'null';
              try {
                const s = String(a);
                // Truncar strings longas (ex: dados binários em base64)
                return s.length > 120 ? s.slice(0, 120) + '…' : s;
              } catch (_) { return '[?]'; }
            });

            const tag = className.split('.').pop() + '.' + mName;
            console.log('[Java] ' + tag + '(' + argStrs.join(', ') + ')');

            const ret = overload.apply(this, arguments);
            try {
              const retStr = ret === null || ret === undefined ? 'null'
                           : String(ret).slice(0, 120);
              console.log('[Java]   → ' + retStr);
            } catch (_) {}
            return ret;
          };
          hooked++;
        });
      } catch (_) {}
    });

    console.log('[Java] ' + className + '  (' + hooked + ' overloads hookados)');
  } catch (e) {
    console.log('[Java] falha em ' + className + ': ' + e.message);
  }
}

// ── Enumeração e hook ─────────────────────────────────────────────────────────

function startHooks() {
  Java.perform(() => {
    console.log('[Java] enumerando classes...');
    const found = [];

    Java.enumerateLoadedClasses({
      onMatch(name) {
        const lower = name.toLowerCase();
        if (KEYWORDS.some(k => lower.includes(k))) {
          found.push(name);
        }
      },
      onComplete() {
        console.log('[Java] ' + found.length + ' classes encontradas:');
        found.forEach(n => console.log('  ' + n));
        console.log('');
        found.forEach(hookJavaClass);

        if (found.length === 0) {
          console.log('[Java] nenhuma classe encontrada com os keywords atuais.');
          console.log('[Java] aguardando 5s e tentando novamente...');
          setTimeout(() => {
            Java.perform(() => {
              const found2 = [];
              Java.enumerateLoadedClasses({
                onMatch(name) {
                  // Segunda tentativa: net.* e com.* que parecem SDK
                  if (/^(com|net)\.(netease|ntes|nt)/i.test(name)) found2.push(name);
                },
                onComplete() {
                  console.log('[Java] 2ª tentativa: ' + found2.length + ' classes');
                  found2.forEach(n => console.log('  ' + n));
                  found2.forEach(hookJavaClass);
                }
              });
            });
          }, 5000);
        }
      }
    });
  });
}

// ── Main ──────────────────────────────────────────────────────────────────────

console.log('[JNI] iniciando — aguardando Java runtime...');
waitForJava(startHooks);
