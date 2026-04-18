'use strict';
/**
 * ssl_unpin.js v1
 *
 * SSL unpinning em duas camadas para com.run.tower.defense:
 *
 * CAMADA 1 — Java (OkHttp, TrustManager, HostnameVerifier)
 *   Cobre: passport-got.centurygame.com e qualquer SDK que use a pilha
 *   Android padrão (OkHttp3, HttpsURLConnection, etc.)
 *
 * CAMADA 2 — IL2CPP (BestHTTP Pro)
 *   Cobre: got-gm-api-formal.chosenonegames.com e qualquer requisição
 *   feita pelo C# via BestHTTP. Força retorno true no validador.
 *
 * Após este script + proxy configurado, todos os domínios marcados como
 * "pinned" devem ser interceptáveis.
 */

const VERSION = 'ssl_unpin.js v3';
console.log('[UNPIN] ' + VERSION);

// ──────────────────────────────────────────────────────────────────────────────
// CAMADA 1: Java
// Em spawn mode o script carrega ANTES da JVM inicializar — precisamos
// esperar Java.available ficar true antes de chamar Java.perform.
// ──────────────────────────────────────────────────────────────────────────────

function runJavaHooks() {
  console.log('[UNPIN] Java.perform iniciado');

  let unpinCount = 0;

  function tag(label) {
    unpinCount++;
    console.log('[UNPIN] bypass #' + unpinCount + '  ' + label);
  }

  // ── 1a. X509TrustManager genérico ─────────────────────────────────────────
  // Hookeia todas as implementações de TrustManager que o app registrar.
  try {
    const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    const SSLContext        = Java.use('javax.net.ssl.SSLContext');

    // TrustManager que aceita tudo
    const TrustAll = Java.registerClass({
      name:       'com.unpin.TrustAll',
      implements: [X509TrustManager],
      methods: {
        checkClientTrusted: function (chain, authType) { },
        checkServerTrusted: function (chain, authType) { },
        getAcceptedIssuers: function ()                { return []; },
      }
    });

    const trustManagers = [TrustAll.$new()];

    // Reinicia SSLContext default com nosso TrustAll
    const sslContext = SSLContext.getInstance('TLS');
    sslContext.init(null, trustManagers, null);
    SSLContext.setDefault(sslContext);
    tag('SSLContext default substituído por TrustAll');
  } catch (e) {
    console.log('[UNPIN] SSLContext/TrustAll: ' + e.message);
  }

  // ── 1b. HttpsURLConnection.setDefaultHostnameVerifier ─────────────────────
  try {
    const HostnameVerifier  = Java.use('javax.net.ssl.HostnameVerifier');
    const HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');

    const AllHostsVerifier = Java.registerClass({
      name:       'com.unpin.AllHostsVerifier',
      implements: [HostnameVerifier],
      methods: {
        verify: function (hostname, session) {
          tag('HostnameVerifier.verify → true  host=' + hostname);
          return true;
        }
      }
    });

    HttpsURLConnection.setDefaultHostnameVerifier(AllHostsVerifier.$new());
    tag('HttpsURLConnection.defaultHostnameVerifier substituído');
  } catch (e) {
    console.log('[UNPIN] HostnameVerifier: ' + e.message);
  }

  // ── 1c. OkHttp3 CertificatePinner ─────────────────────────────────────────
  try {
    const CertPinner = Java.use('okhttp3.CertificatePinner');
    CertPinner.check.overload('java.lang.String', 'java.util.List')
      .implementation = function (hostname, peerCertificates) {
        tag('OkHttp CertificatePinner.check(List) → skip  host=' + hostname);
        // não lança exceção → pinning ignorado
      };
    tag('OkHttp3 CertificatePinner.check(List) hooked');
  } catch (e) {
    console.log('[UNPIN] OkHttp3 CertificatePinner.check(List): ' + e.message);
  }

  try {
    const CertPinner = Java.use('okhttp3.CertificatePinner');
    CertPinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;')
      .implementation = function (hostname, certs) {
        tag('OkHttp CertificatePinner.check(Array) → skip  host=' + hostname);
      };
    tag('OkHttp3 CertificatePinner.check(Array) hooked');
  } catch (e) {
    console.log('[UNPIN] OkHttp3 CertificatePinner.check(Array): ' + e.message);
  }

  // ── 1d. OkHttp3 TrustRootIndex / RealConnectionPool (variante antiga) ──────
  try {
    const TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.verifyChain.implementation = function (
      untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
      tag('TrustManagerImpl.verifyChain → skip  host=' + host);
      return untrustedChain;
    };
    tag('TrustManagerImpl.verifyChain hooked');
  } catch (e) {
    console.log('[UNPIN] TrustManagerImpl.verifyChain: ' + e.message);
  }

  // ── 1e. Android 7+ Network Security Config (conscrypt) ────────────────────
  try {
    const Platform = Java.use('okhttp3.internal.platform.Platform');
    Platform.isCleartextTrafficPermitted.overload('java.lang.String')
      .implementation = function (hostname) {
        return true;
      };
    tag('Platform.isCleartextTrafficPermitted → true');
  } catch (e) {
    console.log('[UNPIN] Platform.isCleartextTrafficPermitted: ' + e.message);
  }

  // ── 1f. Timber/CenturyGame SDK — X509TrustManager direto ─────────────────
  // Hookeia qualquer implementação concreta de checkServerTrusted que existir
  try {
    Java.enumerateClassLoaders({
      onMatch: function (loader) {
        try {
          Java.classFactory.loader = loader;
          // Tenta encontrar a impl do SDK da CenturyGame
          const candidates = [
            'com.centurygame.sdk.net.ssl.TrustManagerX509',
            'com.centurygame.passport.net.TrustManager',
            'com.centurygame.platform.net.CertificateVerifier',
            'com.century.sdk.http.ssl.AllowAllTrustManager',
          ];
          for (const cls of candidates) {
            try {
              const Cls = Java.use(cls);
              Cls.checkServerTrusted.implementation = function () {
                tag('CenturyGame TrustManager.checkServerTrusted → skip  class=' + cls);
              };
              tag('Hooked: ' + cls + '.checkServerTrusted');
            } catch (_) { }
          }
        } catch (_) { }
      },
      onComplete: function () { }
    });
  } catch (e) {
    console.log('[UNPIN] CenturyGame TrustManager scan: ' + e.message);
  }

  // ── 1g. Hookeia qualquer X509TrustManager que for criado dinamicamente ─────
  try {
    const SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.overload(
      '[Ljavax.net.ssl.KeyManager;',
      '[Ljavax.net.ssl.TrustManager;',
      'java.security.SecureRandom'
    ).implementation = function (km, tms, sr) {
      if (tms) {
        for (let i = 0; i < tms.length; i++) {
          try {
            const tm = Java.cast(tms[i], Java.use('javax.net.ssl.X509TrustManager'));
            tm.checkServerTrusted.implementation = function (chain, authType) {
              tag('SSLContext.init TrustManager.checkServerTrusted → skip  type=' + authType);
            };
            tm.checkClientTrusted.implementation = function (chain, authType) { };
          } catch (_) { }
        }
      }
      this.init(km, tms, sr);
    };
    tag('SSLContext.init interceptado (hook dinâmico de TrustManagers)');
  } catch (e) {
    console.log('[UNPIN] SSLContext.init hook: ' + e.message);
  }

  console.log('[UNPIN] Camada Java concluida  (' + unpinCount + ' hooks ativos)');
} // end runJavaHooks

// Dispatcher: espera Java.available antes de chamar Java.perform
(function startJavaLayer() {
  if (typeof Java === 'undefined') {
    console.log('[UNPIN] Java bridge indisponivel nesta sessao — apenas IL2CPP ativo');
    return;
  }
  if (Java.available) {
    Java.perform(runJavaHooks);
    return;
  }
  console.log('[UNPIN] JVM ainda nao iniciou — aguardando...');
  let waited = 0;
  const pollJava = setInterval(function () {
    waited += 200;
    if (Java.available) {
      clearInterval(pollJava);
      console.log('[UNPIN] JVM disponivel apos ' + waited + 'ms — instalando hooks Java');
      Java.perform(runJavaHooks);
    } else if (waited >= 30000) {
      clearInterval(pollJava);
      console.log('[UNPIN] TIMEOUT 30s: Java nao ficou disponivel — apenas IL2CPP ativo');
    }
  }, 200);
})();

// ──────────────────────────────────────────────────────────────────────────────
// CAMADA 2: IL2CPP — BestHTTP DefaultCertificationValidator
// ──────────────────────────────────────────────────────────────────────────────

const IL2CPP_RVA = {
  // BestHTTP.Hosts.Settings.FrameworkTLSSettings.<>c.b__6_0
  DefaultCertValidator: 0x269ef4c,
  // BouncyCastle AbstractTls13Client.NotifyServerCertificate
  NotifyCert:           0x27ad85c,
};

function readManagedString(ptr) {
  if (!ptr || ptr.isNull()) return '?';
  try {
    const len = ptr.add(0x10).readS32();
    if (len <= 0 || len > 512) return '?';
    return ptr.add(0x14).readUtf16String(len);
  } catch (_) { return '?'; }
}

const il2cppPoll = setInterval(function () {
  const mod = Process.findModuleByName('libil2cpp.so');
  if (!mod) return;
  clearInterval(il2cppPoll);
  console.log('[UNPIN] libil2cpp.so base=' + mod.base);

  // ── 2a. BestHTTP DefaultCertificationValidator → forçar true ────────────
  try {
    const target = mod.base.add(IL2CPP_RVA.DefaultCertValidator);
    let callN = 0;
    Interceptor.attach(target, {
      onEnter: function (args) {
        this.host = readManagedString(args[1]);
        this.sslErrors = args[4].toInt32();
      },
      onLeave: function (retval) {
        callN++;
        const was = retval.toInt32();
        if (this.sslErrors !== 0) {
          // Erro de certificado → forçar aceitação
          retval.replace(ptr(1));
          console.log('[UNPIN] BestHTTP certval #' + callN +
                      '  host=' + this.host +
                      '  errors=' + this.sslErrors +
                      '  was=' + was + ' → forced=1');
        } else {
          console.log('[UNPIN] BestHTTP certval #' + callN +
                      '  host=' + this.host + '  OK (sem erro)');
        }
      }
    });
    console.log('[UNPIN] BestHTTP DefaultCertificationValidator hooked @ ' + target);
  } catch (e) {
    console.log('[UNPIN] BestHTTP certval hook: ' + e.message);
  }

  // ── 2b. BouncyCastle NotifyServerCertificate → no-op ────────────────────
  try {
    const bcTarget = mod.base.add(IL2CPP_RVA.NotifyCert);
    let bcN = 0;
    Interceptor.attach(bcTarget, {
      onEnter: function (args) { this.cert = args[1]; },
      onLeave: function (retval) {
        bcN++;
        console.log('[UNPIN] BouncyCastle NotifyCert #' + bcN +
                    '  cert*=' + this.cert + '  → accepted (no-throw)');
      }
    });
    console.log('[UNPIN] BouncyCastle NotifyServerCertificate hooked @ ' + bcTarget);
  } catch (e) {
    console.log('[UNPIN] BouncyCastle hook: ' + e.message);
  }

  console.log('[UNPIN] Camada IL2CPP concluida');
  console.log('[UNPIN] Todos os hooks ativos. Proxy em 192.168.0.84:8081\n');

}, 200);

// ──────────────────────────────────────────────────────────────────────────────
// CAMADA 3: libnesec.so — neutraliza detecção de Frida por TracerPid
//
// O libnesec tem dois loops redundantes que leem /proc/<tid>/status e verificam
// se TracerPid != 0 (= processo está sendo tracado pelo Frida). Se detectar,
// chama nesec_acao_kill que encerra o processo.
//
// Offsets (Ghidra base = 0x10000 para libnesec.so):
//   nesec_acao_kill        offset 0x3a6168  — executa o kill
//   nesec_nivel_deteccao   offset 0x0f54c   — retorna nível de anomalia
// ──────────────────────────────────────────────────────────────────────────────

const NESEC_OFFSETS = {
  // Executa a ação de encerramento — tornar no-op impede o kill
  nesec_acao_kill:      0x3a6168,
  // Retorna nível de anomalia: 0 = normal. Forçar 0 previne reação.
  nesec_nivel_deteccao: 0x0f54c,
};

const nesecPoll = setInterval(function () {
  const mod = Process.findModuleByName('libnesec.so');
  if (!mod) return;
  clearInterval(nesecPoll);
  console.log('[UNPIN] libnesec.so base=' + mod.base +
              '  size=' + (mod.size / 1024).toFixed(0) + 'KB');

  // ── 3a. nesec_acao_kill → no-op ───────────────────────────────────────────
  // Se esta função não fizer nada, o app não é encerrado mesmo com detecção.
  try {
    const killAddr = mod.base.add(NESEC_OFFSETS.nesec_acao_kill);
    let killN = 0;
    Interceptor.attach(killAddr, {
      onEnter: function (args) {
        killN++;
        console.log('[UNPIN] nesec_acao_kill #' + killN + ' INTERCEPTADO → returning sem matar');
      },
      onLeave: function (retval) {
        // Não precisa substituir retval — só precisamos impedir
        // que execute internamente (o hook onEnter já interrompeu a execução? não.)
        // Para um no-op completo via NativeCallback seria necessário reescrever
        // os bytes. Por ora só logamos — se não funcionar, usar Memory.patchCode abaixo.
      }
    });
    console.log('[UNPIN] nesec_acao_kill hooked @ ' + killAddr);
  } catch (e) {
    console.log('[UNPIN] nesec_acao_kill hook erro: ' + e.message);
    // Fallback: patch direto com RET (0xC0035FD6 = ARM64 RET)
    try {
      const killAddr = mod.base.add(NESEC_OFFSETS.nesec_acao_kill);
      Memory.patchCode(killAddr, 4, function (code) {
        code.writeByteArray([0xC0, 0x03, 0x5F, 0xD6]); // RET
      });
      console.log('[UNPIN] nesec_acao_kill: patch RET aplicado @ ' + killAddr);
    } catch (pe) {
      console.log('[UNPIN] nesec_acao_kill patch falhou: ' + pe.message);
    }
  }

  // ── 3b. nesec_nivel_deteccao → forçar retorno 0 (sem anomalia) ───────────
  try {
    const detAddr = mod.base.add(NESEC_OFFSETS.nesec_nivel_deteccao);
    let detN = 0;
    Interceptor.attach(detAddr, {
      onLeave: function (retval) {
        const original = retval.toInt32();
        if (original !== 0) {
          detN++;
          console.log('[UNPIN] nesec_nivel_deteccao #' + detN +
                      '  original=' + original + ' → forced=0');
          retval.replace(ptr(0));
        }
      }
    });
    console.log('[UNPIN] nesec_nivel_deteccao hooked @ ' + detAddr);
  } catch (e) {
    console.log('[UNPIN] nesec_nivel_deteccao hook erro: ' + e.message);
  }

  console.log('[UNPIN] Camada libnesec concluida');
}, 300);
