'use strict';
/**
 * nesec_bypass.js
 * Neutraliza libnesec anti-tampering para prolongar sessão Frida.
 * Usar com --startup-script no Objection.
 */

const NESEC_OFFSETS = {
  nesec_acao_kill:      0x3a6168,
  nesec_nivel_deteccao: 0x0f54c,
};

const RET_ARM64 = [0xc0, 0x03, 0x5f, 0xd6]; // RET

function hookNesec() {
  const mod = Process.findModuleByName('libnesec.so');
  if (!mod) {
    console.log('[NESEC] libnesec.so não encontrada ainda, aguardando...');
    return false;
  }

  console.log('[NESEC] libnesec.so @ ' + mod.base);

  // 1. nesec_acao_kill → NOP (RET imediato)
  try {
    const kill_addr = mod.base.add(NESEC_OFFSETS.nesec_acao_kill);
    Memory.patchCode(kill_addr, 4, code => {
      code.writeByteArray(RET_ARM64);
    });
    console.log('[NESEC] nesec_acao_kill neutralizado @ ' + kill_addr);
  } catch (e) {
    console.log('[NESEC] patchCode kill falhou: ' + e.message);
    // fallback: hook via Interceptor
    try {
      Interceptor.attach(mod.base.add(NESEC_OFFSETS.nesec_acao_kill), {
        onEnter() { console.log('[NESEC] acao_kill interceptado, bloqueando'); },
        onLeave(r) { r.replace(ptr(0)); }
      });
    } catch (e2) {
      console.log('[NESEC] interceptor kill também falhou: ' + e2.message);
    }
  }

  // 2. nesec_nivel_deteccao → sempre retorna 0 (normal)
  try {
    Interceptor.attach(mod.base.add(NESEC_OFFSETS.nesec_nivel_deteccao), {
      onLeave(retval) {
        retval.replace(ptr(0));
      }
    });
    console.log('[NESEC] nesec_nivel_deteccao → 0 fixo');
  } catch (e) {
    console.log('[NESEC] interceptor nivel falhou: ' + e.message);
  }

  return true;
}

// IL2CPP BestHTTP certval bypass (complementa o Java layer do Objection)
function hookBestHTTP() {
  const il2cpp = Process.findModuleByName('libil2cpp.so');
  if (!il2cpp) return;

  const RVA_CERTVAL = 0x269ef4c;
  try {
    Interceptor.attach(il2cpp.base.add(RVA_CERTVAL), {
      onLeave(retval) {
        retval.replace(ptr(1)); // aceita qualquer cert
      }
    });
    console.log('[CERTVAL] BestHTTP DefaultCertificationValidator bypassed');
  } catch (e) {
    console.log('[CERTVAL] erro: ' + e.message);
  }
}

// Polling até libnesec carregar
const poll = setInterval(() => {
  if (hookNesec()) {
    clearInterval(poll);
    hookBestHTTP();
    console.log('[BYPASS] Todos os hooks instalados.');
  }
}, 200);
