/**
 * explorer_interop.js — Observação de interação entre libs de segurança e o jogo
 *
 * Complemento ao explorer.js — foca na camada de comunicação entre
 * libnesec/libNetHTProtect e o runtime do jogo (libil2cpp + libunity).
 *
 * Apenas observação. Sem modificação de memória.
 *
 * Uso (junto com explorer.js):
 *   frida -U -f com.run.tower.defense -l explorer.js -l explorer_interop.js --no-pause
 *
 * Ou sozinho:
 *   frida -U -f com.run.tower.defense -l explorer_interop.js --no-pause
 */

'use strict';

function log(tag, msg) {
  console.log(`[${tag}] ${msg}`);
}

// ─── 1. Observar chamadas JNI vindas das libs de segurança ───────────────────
// As libs nativas chamam Java/Kotlin via JNI para interagir com o ActivityManager
// Observar FindClass, GetMethodID e CallXMethod revela quais APIs Java elas usam

function observeJNI() {
  try {
    const jni = Java.vm.getEnv();
    log('JNI', 'Ambiente JNI disponível');
  } catch(_) {
    log('JNI', 'JNI não disponível ainda — aguardando...');
  }

  // Hook nos métodos JNI da libart para ver chamadas Java originadas de libs nativas
  const libart = Process.findModuleByName('libart.so');
  if (!libart) { log('JNI', 'libart não encontrada'); return; }

  // FindClass — revela quais classes Java as libs buscam
  try {
    const findClass = libart.getExportByName('_ZN3art3JNI9FindClassEP7_JNIEnvPKc');
    if (findClass) {
      Interceptor.attach(findClass, {
        onEnter(args) {
          try {
            const className = args[1].readCString();
            // Filtrar apenas classes relevantes (ActivityManager, PackageManager, etc.)
            if (className && (
              className.includes('Activity') ||
              className.includes('Package') ||
              className.includes('Process') ||
              className.includes('Build') ||
              className.includes('System')
            )) {
              log('JNI', `FindClass("${className}") — de ${DebugSymbol.fromAddress(this.returnAddress)}`);
            }
          } catch(_) {}
        }
      });
      log('JNI', `hook FindClass @ ${findClass}`);
    }
  } catch(e) { log('JNI', `FindClass err: ${e.message}`); }

  // CallStaticVoidMethod — revela chamadas de métodos estáticos Java (ex: forceStopPackage)
  try {
    const callStatic = libart.getExportByName('_ZN3art3JNI20CallStaticVoidMethodEP7_JNIEnvP7_jclassP10_jmethodIDz');
    if (callStatic) {
      Interceptor.attach(callStatic, {
        onEnter(args) {
          log('JNI', `CallStaticVoidMethod — class=${args[1]} method=${args[2]} caller=${DebugSymbol.fromAddress(this.returnAddress)}`);
        }
      });
      log('JNI', `hook CallStaticVoidMethod @ ${callStatic}`);
    }
  } catch(e) { log('JNI', `CallStaticVoid err: ${e.message}`); }
}

// ─── 2. Observar a vtable DAT_005a62e8 (interface IL2CPP → libs de segurança) ─
// A libNetHTProtect chama o IL2CPP via vtable com offsets fixos:
//   +0x160 = alloc buffer
//   +0x168 = free buffer
//   +0x180 = memcpy/write
//   +0x558 = input de dados
//   +0x5c0 = pointer
//   +0x600 = release
//   +0x680 = write final

function observeIL2CppVtable() {
  const nethtp = Process.findModuleByName('libNetHTProtect.so');
  if (!nethtp) { log('VTBL', 'libNetHTProtect não encontrada'); return; }

  // DAT_005a62e8 offset na nethtp = 0x005a62e8 - 0x100000 = 0x4a62e8
  const vtableAddr = nethtp.base.add(0x4a62e8);

  setInterval(() => {
    try {
      const vtable = vtableAddr.readPointer();
      if (vtable.isNull()) return;

      // Ler os slots de função da vtable
      const slots = [0x160, 0x168, 0x180, 0x558, 0x5c0, 0x600, 0x680];
      const names = ['alloc', 'free', 'write', 'input', 'pointer', 'release', 'write_final'];

      let info = '';
      slots.forEach((off, i) => {
        try {
          const fn = vtable.add(off).readPointer();
          const sym = DebugSymbol.fromAddress(fn);
          info += `\n    [+0x${off.toString(16)}] ${names[i]} = ${fn} (${sym.moduleName || '?'}!${sym.name || '?'})`;
        } catch(_) {}
      });

      if (info) {
        log('VTBL', `vtable @ ${vtable}:${info}`);
      }
    } catch(_) {}
  }, 10000); // uma vez a cada 10s para não poluir o log
}

// ─── 3. Observar chamadas de pthread entre as libs ────────────────────────────
// Revela quando cada lib cria threads e qual função elas executam

function observeThreadCreation() {
  try {
    const pthreadCreate = Module.getExportByName('libc.so', 'pthread_create');
    Interceptor.attach(pthreadCreate, {
      onEnter(args) {
        try {
          const startFn   = args[2];
          const startArg  = args[3];
          const sym       = DebugSymbol.fromAddress(startFn);
          const caller    = DebugSymbol.fromAddress(this.returnAddress);
          log('THR', `pthread_create → fn=${startFn} (${sym.moduleName || '?'}!${sym.name || 'anon'}) arg=${startArg} criado por ${caller.moduleName || '?'}!${caller.name || 'anon'}`);
        } catch(_) {}
      }
    });
    log('THR', 'hook pthread_create ok');
  } catch(e) { log('THR', `pthread_create err: ${e.message}`); }
}

// ─── 4. Observar dlopen — carregamento dinâmico de libs ──────────────────────
// Revela quando e como as libs de segurança são carregadas

function observeDlopen() {
  try {
    const dlopen = Module.getExportByName(null, 'dlopen');
    if (dlopen) {
      Interceptor.attach(dlopen, {
        onEnter(args) {
          try {
            const path = args[0].readCString();
            if (path) log('DLOPEN', `dlopen("${path}") por ${DebugSymbol.fromAddress(this.returnAddress)}`);
          } catch(_) {}
        },
        onLeave(ret) {
          log('DLOPEN', `dlopen retornou handle=${ret}`);
        }
      });
      log('DLOPEN', `hook dlopen @ ${dlopen}`);
    }
  } catch(e) { log('DLOPEN', `err: ${e.message}`); }

  // android_dlopen_ext — usado para carregar em namespace isolado (libxt)
  try {
    const dlopenExt = Module.getExportByName(null, 'android_dlopen_ext');
    if (dlopenExt) {
      Interceptor.attach(dlopenExt, {
        onEnter(args) {
          try {
            const path = args[0].readCString();
            log('DLOPEN', `android_dlopen_ext("${path || 'null'}") → namespace isolado`);
          } catch(_) {}
        }
      });
      log('DLOPEN', `hook android_dlopen_ext @ ${dlopenExt}`);
    }
  } catch(e) { log('DLOPEN', `android_dlopen_ext err: ${e.message}`); }
}

// ─── 5. Observar comunicação de rede (qual endereço o payload é enviado) ──────

function observeNetwork() {
  try {
    const connect = Module.getExportByName('libc.so', 'connect');
    Interceptor.attach(connect, {
      onEnter(args) {
        try {
          const sockaddr = args[1];
          const family = sockaddr.readU16();
          if (family === 2) { // AF_INET
            const port = ((sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8());
            const ip = [
              sockaddr.add(4).readU8(),
              sockaddr.add(5).readU8(),
              sockaddr.add(6).readU8(),
              sockaddr.add(7).readU8()
            ].join('.');
            const caller = DebugSymbol.fromAddress(this.returnAddress);
            log('NET', `connect → ${ip}:${port} por ${caller.moduleName || '?'}!${caller.name || 'anon'}`);
          }
        } catch(_) {}
      }
    });
    log('NET', 'hook connect ok');
  } catch(e) { log('NET', `connect err: ${e.message}`); }

  try {
    const send = Module.getExportByName('libc.so', 'send');
    Interceptor.attach(send, {
      onEnter(args) {
        try {
          const len    = args[2].toInt32();
          const caller = DebugSymbol.fromAddress(this.returnAddress);
          // Mostrar primeiros bytes do payload para identificar formato
          const preview = args[1].readByteArray(Math.min(len, 32));
          const hex = preview
            ? Array.from(new Uint8Array(preview)).map(x => x.toString(16).padStart(2,'0')).join(' ')
            : '?';
          log('NET', `send(${len} bytes) por ${caller.moduleName || '?'}!${caller.name || 'anon'} — ${hex}`);
        } catch(_) {}
      }
    });
    log('NET', 'hook send ok');
  } catch(e) { log('NET', `send err: ${e.message}`); }
}

// ─── 6. Observar interação com IL2CPP — chamadas internas do jogo ─────────────

function observeIL2Cpp() {
  const il2cpp = Process.findModuleByName('libil2cpp.so');
  if (!il2cpp) { log('IL2CPP', 'libil2cpp não encontrada'); return; }
  log('IL2CPP', `base=${il2cpp.base}  size=${il2cpp.size}`);

  // il2cpp_runtime_invoke — toda chamada C# passa por aqui
  try {
    const invoke = il2cpp.getExportByName('il2cpp_runtime_invoke');
    if (invoke) {
      let callCount = 0;
      Interceptor.attach(invoke, {
        onEnter(args) {
          callCount++;
          // Logar apenas a cada 100 chamadas para não poluir
          if (callCount % 100 === 0) {
            log('IL2CPP', `il2cpp_runtime_invoke #${callCount} method=${args[0]}`);
          }
        }
      });
      log('IL2CPP', `hook il2cpp_runtime_invoke @ ${invoke}`);
    }
  } catch(e) { log('IL2CPP', `invoke err: ${e.message}`); }

  // il2cpp_array_new — alocações de arrays C# (indica atividade)
  try {
    const arrayNew = il2cpp.getExportByName('il2cpp_array_new');
    if (arrayNew) {
      let allocCount = 0;
      Interceptor.attach(arrayNew, {
        onEnter(args) { allocCount++; },
        onLeave(ret) {
          if (allocCount % 500 === 0) {
            log('IL2CPP', `il2cpp_array_new #${allocCount} → ${ret}`);
          }
        }
      });
      log('IL2CPP', `hook il2cpp_array_new @ ${arrayNew}`);
    }
  } catch(e) { log('IL2CPP', `array_new err: ${e.message}`); }
}

// ─── Execução ─────────────────────────────────────────────────────────────────

function main() {
  log('INIT', 'explorer_interop.js — observação de interação entre libs');

  setTimeout(() => {
    observeDlopen();
    observeThreadCreation();
    observeNetwork();
    observeJNI();
    observeIL2Cpp();
    observeIL2CppVtable();
    log('INIT', 'Todos os observadores ativos.');
  }, 3000);
}

main();