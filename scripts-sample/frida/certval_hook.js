'use strict';
/**
 * certval_hook.js v1
 *
 * Hookeia Best.HTTP.Hosts.Settings.FrameworkTLSSettings.<>c.<.cctor>b__6_0
 * — o DefaultCertificationValidator da biblioteca Best HTTP Pro.
 *
 * Assinatura C#:
 *   Boolean b__6_0(String host, X509Certificate cert, X509Chain chain,
 *                  SslPolicyErrors sslPolicyErrors)
 *
 * SslPolicyErrors (enum, Int32):
 *   None                        = 0  → certificado válido
 *   RemoteCertificateNotAvailable = 1
 *   RemoteCertificateNameMismatch = 2
 *   RemoteCertificateChainErrors  = 4
 *
 * Se a função retornar 1 (true) para sslPolicyErrors != 0 → aceita qualquer cert → MITM possível.
 *
 * RVA: 0x269ef4c  (libil2cpp.so)
 * Ghidra: 0x279ef4c
 *
 * IL2CPP ARM64 — método de instância do compiler-generated <>c:
 *   args[0] = this (<>c instance)
 *   args[1] = host  (System.String*)
 *   args[2] = cert  (X509Certificate*)
 *   args[3] = chain (X509Chain*)
 *   args[4] = sslPolicyErrors (Int32 como NativePointer)
 *   retval  = 0 (false) ou 1 (true)
 */

const VERSION = 'certval_hook.js v2';

// Framework TLS path (FrameworkTLSSettings.<>c.b__6_0)
const RVA_CERTVAL = 0x269ef4c;

// BouncyCastle TLS path (AbstractTls13Client.NotifyServerCertificate)
// Se tiver corpo vazio → aceita qualquer cert sem validar
const RVA_NOTIFY_CERT = 0x27ad85c;

const SSL_ERRORS = {
  0: 'None (válido)',
  1: 'RemoteCertificateNotAvailable',
  2: 'RemoteCertificateNameMismatch',
  4: 'RemoteCertificateChainErrors',
};

function readManagedString(ptr) {
  if (!ptr || ptr.isNull()) return null;
  try {
    const len = ptr.add(0x10).readS32();
    if (len <= 0 || len > 512) return null;
    return ptr.add(0x14).readUtf16String(len);
  } catch (_) { return null; }
}

function main() {
  console.log('[CV] ' + VERSION + ' iniciando...');

  const poll = setInterval(() => {
    const mod = Process.findModuleByName('libil2cpp.so');
    if (!mod) return;
    clearInterval(poll);
    console.log('[CV] libil2cpp.so base=' + mod.base);

    const target = mod.base.add(RVA_CERTVAL);
    console.log('[CV] hook: DefaultCertificationValidator @ ' + target);

    let callCount = 0;
    let trueWithErrors = 0;

    try {
      Interceptor.attach(target, {
        onEnter(args) {
          this.host       = readManagedString(args[1]) || '?';
          this.sslErrors  = args[4].toInt32();
        },
        onLeave(retval) {
          callCount++;
          const ret      = retval.toInt32();  // 0=false, 1=true
          const errName  = SSL_ERRORS[this.sslErrors] || ('0x' + this.sslErrors.toString(16));
          const verdict  = ret ? 'ACEITO' : 'REJEITADO';
          const flag     = (ret && this.sslErrors !== 0) ? '  ⚠ ACEITO COM ERRO' : '';

          if (ret && this.sslErrors !== 0) trueWithErrors++;

          console.log('[CV] #' + callCount +
                      '  host="' + this.host + '"' +
                      '  errors=' + this.sslErrors + ' (' + errName + ')' +
                      '  → ' + verdict + flag);
        }
      });
      console.log('[CV] hook instalado.\n' +
                  '[CV] Use o jogo normalmente — qualquer requisição HTTPS vai aparecer aqui.\n');
    } catch (e) {
      console.log('[!] erro: ' + e.message);
      return;
    }

    // Hook BouncyCastle: NotifyServerCertificate
    // args[0]=this, args[1]=TlsServerCertificate*
    // Se a função retorna imediatamente sem fazer nada → aceita qualquer cert
    let bcCount = 0;
    try {
      const bcTarget = mod.base.add(RVA_NOTIFY_CERT);
      Interceptor.attach(bcTarget, {
        onEnter(args) {
          bcCount++;
          console.log('[CV] BouncyCastle NotifyServerCertificate #' + bcCount +
                      '  cert*=' + args[1]);
        },
        onLeave() {
          // Se chegou aqui sem lançar exceção → cert aceito
          console.log('[CV] BouncyCastle cert ACEITO (sem exceção lançada)');
        }
      });
      console.log('[CV] hook: NotifyServerCertificate (BouncyCastle) @ ' +
                  mod.base.add(RVA_NOTIFY_CERT));
    } catch (e) {
      console.log('[!] NotifyServerCertificate: ' + e.message);
    }

    // Sumário a cada 15s
    setInterval(() => {
      if (callCount === 0) {
        console.log('[CV] nenhuma validação ainda — game ainda não fez requisição HTTPS');
        return;
      }
      console.log('\n[CV] ══ sumário ══  total=' + callCount +
                  '  aceitos_com_erro=' + trueWithErrors);
      if (trueWithErrors > 0) {
        console.log('[CV] ⚠ VULNERÁVEL: validador aceitou certificados com erro ' +
                    trueWithErrors + 'x → MITM possível');
      } else {
        console.log('[CV] certificados válidos aceitos, nenhum erro visto ainda');
        console.log('[CV] para confirmar MITM: configure um proxy e rode com cert autoassinado');
      }
      console.log('');
    }, 15000);

  }, 100);
}

main();
