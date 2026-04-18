'use strict';
/**
 * ifix_tracker.js
 *
 * Detecta em runtime:
 *   - Quais arquivos de patch o IFix carrega
 *   - Quais métodos C# estão mapeados no patch (via PatchManager.readMethod)
 *   - Quais métodos patcheados são efetivamente invocados (VirtualMachine.Execute)
 *   - Se algum hotswap ocorre (ReplaceGlobal)
 */

// RVAs dos métodos IFix (offset relativo à base de libil2cpp.so)
// Ghidra addr - 0x100000 = RVA
const RVA = {
  patchLoad_path:    0x370da08,  // PatchManager.Load(string filepath)
  patchLoad_stream:  0x370dbb8,  // PatchManager.Load(Stream stream, bool checkNew)
  readMethod:        0x3710610,  // PatchManager.readMethod => MethodBase
  getRedirectField:  0x3711168,  // PatchManager.getRedirectField(MethodBase)
  vmExecute:         0x3700e50,  // VirtualMachine.Execute(int methodIndex, ...)
  vmInitGlobal:      0x370d7c8,  // VirtualMachine.InitializeGlobal(Stream)
  vmReplaceGlobal:   0x370d824,  // VirtualMachine.ReplaceGlobal(Stream)
};

// == Utilitários ===============================================================

function readManagedString(ptr) {
  if (!ptr || ptr.isNull()) return null;
  try {
    const len = ptr.add(0x10).readS32();
    if (len <= 0 || len > 2048) return null;
    return ptr.add(0x14).readUtf16String(len);
  } catch (_) { return null; }
}

// Tenta ler o nome de um System.Reflection.RuntimeMethodInfo gerenciado.
// Em IL2CPP, RuntimeMethodInfo guarda o Il2CppMethodInfo* no primeiro campo
// após o header (klass* @ 0x0, monitor @ 0x8, mhandle/IntPtr @ 0x10).
function tryGetMethodBaseName(il2cppMethodGetName, methodBasePtr) {
  if (!methodBasePtr || methodBasePtr.isNull()) return null;
  try {
    const nativePtr = methodBasePtr.add(0x10).readPointer();
    if (!nativePtr || nativePtr.isNull()) return null;
    const namePtr = il2cppMethodGetName(nativePtr);
    if (!namePtr || namePtr.isNull()) return null;
    return namePtr.readUtf8String();
  } catch (_) { return null; }
}

// == Estado global =============================================================

// methodIndex (IFix interno) => nome C# do método patcheado
const methodIndexMap = new Map();

// Contagem de invocações por methodIndex
const execCount = new Map();
let totalExec   = 0;

// Ordem de leitura => methodIndex (IFix indexa na ordem em que readMethod é chamado)
let readOrder = 0;

// == Main ======================================================================

function main() {
  console.log('[IFix] aguardando libil2cpp.so...');

  const poll = setInterval(() => {
    const mod = Process.findModuleByName('libil2cpp.so');
    if (!mod) return;
    clearInterval(poll);

    const base = mod.base;
    console.log('[IFix] base=' + base);

    // Resolver il2cpp_method_get_name uma vez
    let il2cppMethodGetName = null;
    try {
      const fnPtr = mod.getExportByName('il2cpp_method_get_name');
      il2cppMethodGetName = new NativeFunction(fnPtr, 'pointer', ['pointer']);
    } catch (e) {
      console.log('[!] il2cpp_method_get_name não encontrado: ' + e.message);
    }

    // == 1. PatchManager.Load(string filepath) ==============================
    try {
      Interceptor.attach(base.add(RVA.patchLoad_path), {
        onEnter(args) {
          const path = readManagedString(args[1]);
          console.log('\n[IFix] ══ PatchManager.Load(path) ══');
          console.log('  path  = "' + (path || '?') + '"');
        },
        onLeave(retval) {
          console.log('  vm    = ' + retval + (retval.isNull() ? ' (null!)' : ' OK'));
        }
      });
      console.log('[IFix] hook instalado: PatchManager.Load(path)');
    } catch (e) { console.log('[!] Load(path): ' + e.message); }

    // == 2. PatchManager.Load(Stream, bool) ================================
    try {
      Interceptor.attach(base.add(RVA.patchLoad_stream), {
        onEnter(args) {
          const checkNew = args[2].toInt32();
          console.log('\n[IFix] ══ PatchManager.Load(stream, checkNew=' + checkNew + ') ══');
        },
        onLeave(retval) {
          console.log('  vm    = ' + retval + (retval.isNull() ? ' (null!)' : ' OK'));
        }
      });
      console.log('[IFix] hook instalado: PatchManager.Load(stream)');
    } catch (e) { console.log('[!] Load(stream): ' + e.message); }

    // == 3. PatchManager.readMethod => constrói mapa índice => nome ==========
    // readMethod é chamado em loop durante o Load, uma vez por método no patch.
    // A ordem de retorno corresponde ao methodIndex interno do IFix.
    try {
      Interceptor.attach(base.add(RVA.readMethod), {
        onLeave(retval) {
          const idx = readOrder++;
          if (!retval || retval.isNull()) return;

          let name = null;
          if (il2cppMethodGetName) {
            name = tryGetMethodBaseName(il2cppMethodGetName, retval);
          }

          if (name) {
            methodIndexMap.set(idx, name);
            console.log('[IFix] patch[' + idx + '] = ' + name);
          } else {
            // Sem nome - registra o ponteiro para análise posterior
            methodIndexMap.set(idx, '<método@' + retval + '>');
            console.log('[IFix] patch[' + idx + '] = <sem nome, MethodBase@' + retval + '>');
          }
        }
      });
      console.log('[IFix] hook instalado: PatchManager.readMethod');
    } catch (e) { console.log('[!] readMethod: ' + e.message); }

    // == 4. PatchManager.getRedirectField ==================================
    // Retorna non-null apenas para métodos que TÊM redirect ativo.
    // Isso confirma quais métodos do APK foram efetivamente substituídos.
    try {
      Interceptor.attach(base.add(RVA.getRedirectField), {
        onEnter(args) {
          this.methodBase = args[1];
        },
        onLeave(retval) {
          if (retval && !retval.isNull()) {
            let name = null;
            if (il2cppMethodGetName) {
              name = tryGetMethodBaseName(il2cppMethodGetName, this.methodBase);
            }
            console.log('[IFix] REDIRECT ATIVO: ' + (name || '<MethodBase@' + this.methodBase + '>'));
          }
        }
      });
      console.log('[IFix] hook instalado: PatchManager.getRedirectField');
    } catch (e) { console.log('[!] getRedirectField: ' + e.message); }

    // == 5. VirtualMachine.Execute =========================================
    // args[0]=this, args[1]=methodIndex(int), args[2]=call&, args[3]=argsCount
    try {
      Interceptor.attach(base.add(RVA.vmExecute), {
        onEnter(args) {
          const idx   = args[1].toInt32();
          const count = (execCount.get(idx) || 0) + 1;
          execCount.set(idx, count);
          totalExec++;

          if (count === 1) {
            const name = methodIndexMap.get(idx) || '?';
            console.log('[IFix] Execute[' + idx + '] 1ª invocação => ' + name);
          }
        }
      });
      console.log('[IFix] hook instalado: VirtualMachine.Execute');
    } catch (e) { console.log('[!] VirtualMachine.Execute: ' + e.message); }

    // == 6. InitializeGlobal / ReplaceGlobal ===============================
    try {
      Interceptor.attach(base.add(RVA.vmInitGlobal), {
        onEnter() {
          console.log('\n[IFix] VirtualMachine.InitializeGlobal — patch global sendo carregado');
        }
      });
      Interceptor.attach(base.add(RVA.vmReplaceGlobal), {
        onEnter() {
          console.log('\n[IFix] ⚠ VirtualMachine.ReplaceGlobal — HOTSWAP em runtime!');
        }
      });
      console.log('[IFix] hook instalado: InitializeGlobal / ReplaceGlobal');
    } catch (e) { console.log('[!] InitializeGlobal/ReplaceGlobal: ' + e.message); }

    // == 7. Sumário periódico ========================================
    setInterval(() => {
      if (totalExec === 0 && methodIndexMap.size === 0) return;

      console.log('\n[IFix] ══ Sumário ══');
      console.log('  Métodos no patch : ' + methodIndexMap.size);
      console.log('  Execute calls    : ' + totalExec);
      console.log('  Índices únicos   : ' + execCount.size);

      if (execCount.size > 0) {
        console.log('  Top chamados:');
        const sorted = [...execCount.entries()]
          .sort((a, b) => b[1] - a[1])
          .slice(0, 15);
        for (const [idx, count] of sorted) {
          const name = methodIndexMap.get(idx) || '?';
          console.log('    [' + idx + '] ' + count + 'x  ' + name);
        }
      }
    }, 30000);

  }, 100);
}

main();
