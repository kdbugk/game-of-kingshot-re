'use strict';
/**
 * initdecrypt_hook.js v1
 *
 * Hookeia NetSecProtect.initDecrypt(String cipherText) em libil2cpp.so.
 * A função é chamada ~10-15x durante a inicialização do SDK NetEase,
 * uma vez por string hardcoded cifrada (strUUU_0, strCCC_0, etc.).
 *
 * Cada chamada revela um par cifrado → texto claro.
 *
 * RVA: 0x19e1c2c  (libil2cpp.so)
 * Ghidra: 0x1ae1c2c
 *
 * IL2CPP ARM64 instance method:
 *   args[0] = this  (NetSecProtect MonoBehaviour instance)
 *   args[1] = cipherText  (System.String*)
 *   retval  = System.String* (texto claro)
 */

const VERSION = 'initdecrypt_hook.js v3';

// NetSecProtect (Assembly-CSharp-firstpass.dll)
const RVA_INIT_DECRYPT = 0x19e1c2c;  // initDecrypt(String) → String
const RVA_INIT         = 0x19e2714;  // init(String productId, HTPCallback, HTProtectConfig)

// Manager (Assembly-CSharp.dll) — chamado pela lógica do jogo
const RVA_MGR_INIT     = 0x1a4fa54;  // InitNetSecProtect(productId, serverType, channel, ...)
const RVA_MGR_INIT_EX  = 0x1a4fe7c;  // InitNetSecProtectEx(productId, htpConfig)

// XLua wrappers (Assembly-CSharp.dll) — chamados pelo Lua via CS.*
const RVA_LUA_INIT         = 0x1cb311c;  // NetEase_NetSecProtectWrap.init(LuaState)
const RVA_LUA_SAFE_COMM    = 0x1cb49dc;  // NetEase_NetSecProtectWrap.safeCommToServerV30
const RVA_LUA_SAFE_COMM_B  = 0x1cb4778;  // NetEase_NetSecProtectWrap.safeCommToServerByteV30
const RVA_LUA_GET_TOKEN    = 0x1cb547c;  // NetEase_NetSecProtectWrap.getToken
const RVA_LUA_REGISTER     = 0x1cb5d98;  // NetEase_NetSecProtectWrap.Register (quando o SDK é registrado no Lua)

// ── Leitura de String IL2CPP ──────────────────────────────────────────────────
// Layout de System.String em IL2CPP:
//   +0x00  klass*          (ponteiro para MonoClass)
//   +0x08  monitor         (null normalmente)
//   +0x10  m_stringLength  (int32 — número de chars, não bytes)
//   +0x14  m_firstChar     (início dos chars UTF-16LE)

function readManagedString(ptr) {
  if (!ptr || ptr.isNull()) return null;
  try {
    const len = ptr.add(0x10).readS32();
    if (len <= 0 || len > 4096) return null;
    return ptr.add(0x14).readUtf16String(len);
  } catch (_) { return null; }
}

// ── Main ──────────────────────────────────────────────────────────────────────

function main() {
  console.log('[ID] ' + VERSION + ' iniciando...');
  console.log('[ID] aguardando libil2cpp.so...');

  const poll = setInterval(() => {
    const mod = Process.findModuleByName('libil2cpp.so');
    if (!mod) return;
    clearInterval(poll);
    console.log('[ID] libil2cpp.so base=' + mod.base +
                '  size=' + (mod.size / 1024 / 1024).toFixed(0) + 'MB');

    const hookSimple = (label, rva) => {
      try {
        const fn = mod.base.add(rva);
        Interceptor.attach(fn, {
          onEnter() { console.log('[ID] ► ' + label + ' chamado'); }
        });
        console.log('[ID] hook: ' + label + ' @ ' + fn);
      } catch (e) { console.log('[!] ' + label + ': ' + e.message); }
    };

    // Camada C# — manager e core
    hookSimple('InitNetSecProtect',          RVA_MGR_INIT);
    hookSimple('InitNetSecProtectEx',        RVA_MGR_INIT_EX);
    hookSimple('NetSecProtect.init()',       RVA_INIT);

    // Camada XLua — wrappers chamados pelo Lua
    hookSimple('Lua:Register',               RVA_LUA_REGISTER);
    hookSimple('Lua:init',                   RVA_LUA_INIT);
    hookSimple('Lua:safeCommToServerV30',    RVA_LUA_SAFE_COMM);
    hookSimple('Lua:safeCommToServerByteV30',RVA_LUA_SAFE_COMM_B);
    hookSimple('Lua:getToken',               RVA_LUA_GET_TOKEN);

    // Hook principal: initDecrypt — captura pares cifrado → texto claro
    const target = mod.base.add(RVA_INIT_DECRYPT);
    let callCount = 0;
    const results = [];

    try {
      Interceptor.attach(target, {
        onEnter(args) {
          this.cipher = readManagedString(args[1]);
        },
        onLeave(retval) {
          callCount++;
          const plain  = readManagedString(retval);
          const cipher = this.cipher || '?';
          results.push({ cipher, plain });
          console.log('[ID] #' + callCount +
                      '  cipher="' + cipher + '"' +
                      '  →  plain="' + (plain || 'null') + '"');
        }
      });
      console.log('[ID] hook: initDecrypt @ ' + target);
    } catch (e) {
      console.log('[!] initDecrypt: ' + e.message);
    }

    console.log('\n[ID] todos os hooks instalados.\n' +
                '[ID] IMPORTANTE: complete o LOGIN no jogo para disparar o SDK NetEase.\n' +
                '[ID] O SDK só é inicializado após autenticação com o servidor.\n');

    // Sumário a cada 15s
    setInterval(() => {
      if (results.length === 0) return;
      console.log('\n[ID] ══ sumário (' + results.length + ' strings decifradas) ══');
      results.forEach((r, i) => {
        console.log('  [' + (i + 1) + '] "' + r.cipher + '"  →  "' + (r.plain || 'null') + '"');
      });
      console.log('');
    }, 15000);

  }, 100);
}

main();
