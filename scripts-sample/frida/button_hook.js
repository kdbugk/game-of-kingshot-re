'use strict';
/**
 * button_hook.js v1
 *
 * Intercepta cliques e validações de botões no cliente Unity (IL2CPP).
 *
 * O que captura:
 *   1. ButtonEx.OnPointerClick  — todo clique em botão customizado do jogo
 *   2. Button.Press (UnityEngine) — botões Unity padrão
 *   3. ButtonEx.set_interactable — quando o jogo habilita/desabilita um botão
 *   4. ButtonEx.SetDisableKey    — chave de condição que desabilita o botão
 *   5. ClickListener.Click       — dispatch de click (após validação)
 *
 * Cada evento mostra: nome do GameObject, estado interactable, callstack resumida.
 */

const VERSION = 'button_hook.js v1';

// ── RVAs extraídos do dump IL2CPP ────────────────────────────────────────────
const RVA = {
  // UnityEngine.UI.ButtonEx (Assembly-CSharp.dll, base libil2cpp.so)
  ButtonEx_OnPointerClick:   0x23bed78,
  ButtonEx_get_interactable: 0x23bec0c,
  ButtonEx_set_interactable: 0x23bec54,
  ButtonEx_SetDisableKey:    0x23bf348,
  ButtonEx_OnPointerDown:    0x23bf3ac,

  // UnityEngine.UI.Button (UnityEngine.UI.dll, base libil2cpp.so)
  Button_Press:              0x3c105bc,
  Button_OnPointerClick:     0x3c10654,

  // ClickListener (Assembly-CSharp.dll)
  ClickListener_Click:       0x23a139c,
  ClickListener_OnPointerClick: 0x23a12f4,
  OnlyClickListener_Click:   0x2481510,

  // UnityEngine helpers (UnityEngine.CoreModule.dll)
  Object_get_name:           0x3b5e8f4,
  Component_get_gameObject:  0x3b56c18,
};

// ── helpers ───────────────────────────────────────────────────────────────────

let il2cppBase = null;

function getBase() {
  if (il2cppBase) return il2cppBase;
  const mod = Process.findModuleByName('libil2cpp.so');
  if (!mod) return null;
  il2cppBase = mod.base;
  return il2cppBase;
}

function addr(rva) {
  const base = getBase();
  if (!base) return null;
  return base.add(rva);
}

// Lê string IL2CPP (UTF-16LE): struct { vtable*, monitor*, int length, char16[] }
function readIl2cppString(strPtr) {
  try {
    if (!strPtr || strPtr.isNull()) return '<null>';
    const len = strPtr.add(16).readS32();
    if (len <= 0 || len > 512) return `<string len=${len}>`;
    const chars = [];
    for (let i = 0; i < len; i++) {
      chars.push(strPtr.add(20 + i * 2).readU16());
    }
    return String.fromCharCode(...chars);
  } catch (_) {
    return '<err>';
  }
}

// Chama Component.get_gameObject(this) → ponteiro GameObject
let _get_gameObject = null;
function getGameObject(component) {
  try {
    if (!_get_gameObject) {
      const a = addr(RVA.Component_get_gameObject);
      if (!a) return null;
      _get_gameObject = new NativeFunction(a, 'pointer', ['pointer']);
    }
    return _get_gameObject(component);
  } catch (_) { return null; }
}

// Chama Object.get_name(this) → ponteiro Il2CppString
let _get_name = null;
function getObjectName(obj) {
  try {
    if (!_get_name) {
      const a = addr(RVA.Object_get_name);
      if (!a) return '?';
      _get_name = new NativeFunction(a, 'pointer', ['pointer']);
    }
    const strPtr = _get_name(obj);
    return readIl2cppString(strPtr);
  } catch (_) { return '?'; }
}

// Retorna "NomeDoGameObject/NomeDoComponente" a partir do ponteiro do componente
function componentLabel(thisPtr) {
  try {
    const go = getGameObject(thisPtr);
    const goName = go ? getObjectName(go) : '?';
    const compName = getObjectName(thisPtr);
    if (compName && compName !== goName && compName !== '?') {
      return `${goName} [${compName}]`;
    }
    return goName;
  } catch (_) { return '?' }
}

// Callstack resumida (2 frames internos ignorados)
function shortStack() {
  try {
    return Thread.backtrace(this.context, Backtracer.ACCURATE)
      .slice(2, 6)
      .map(a => {
        const sym = DebugSymbol.fromAddress(a);
        return sym.name ? sym.name.slice(0, 40) : a.toString();
      })
      .join(' <- ');
  } catch (_) { return ''; }
}

// ── contador de eventos ───────────────────────────────────────────────────────
let evtN = 0;
function log(tag, label, extra) {
  evtN++;
  const msg = `[BTN#${evtN}] ${tag}  "${label}"${extra ? '  ' + extra : ''}`;
  console.log(msg);
  send({ type: 'button_event', tag, label, extra, n: evtN });
}

// ── hooks ─────────────────────────────────────────────────────────────────────

function hookButtonEx() {
  // 1. ButtonEx.OnPointerClick — clique principal do jogo
  const onClickAddr = addr(RVA.ButtonEx_OnPointerClick);
  if (onClickAddr) {
    Interceptor.attach(onClickAddr, {
      onEnter: function (args) {
        this.label = componentLabel(args[0]);
      },
      onLeave: function () {
        log('CLICK', this.label);
      }
    });
    console.log('[BTN] hook ButtonEx.OnPointerClick @ ' + onClickAddr);
  }

  // 2. ButtonEx.set_interactable — liga/desliga botão
  const setIntAddr = addr(RVA.ButtonEx_set_interactable);
  if (setIntAddr) {
    Interceptor.attach(setIntAddr, {
      onEnter: function (args) {
        this.label = componentLabel(args[0]);
        this.value = args[1].toInt32() !== 0;
      },
      onLeave: function () {
        log('INTERACTABLE', this.label, `enabled=${this.value}`);
      }
    });
    console.log('[BTN] hook ButtonEx.set_interactable @ ' + setIntAddr);
  }

  // 3. ButtonEx.SetDisableKey — condição que bloqueia o botão
  const disKeyAddr = addr(RVA.ButtonEx_SetDisableKey);
  if (disKeyAddr) {
    Interceptor.attach(disKeyAddr, {
      onEnter: function (args) {
        this.label = componentLabel(args[0]);
        this.key = readIl2cppString(args[1]);
      },
      onLeave: function () {
        log('DISABLE_KEY', this.label, `key="${this.key}"`);
      }
    });
    console.log('[BTN] hook ButtonEx.SetDisableKey @ ' + disKeyAddr);
  }
}

function hookButtonBase() {
  // 4. Button.Press — base Unity (dispara onClick.Invoke internamente)
  const pressAddr = addr(RVA.Button_Press);
  if (pressAddr) {
    Interceptor.attach(pressAddr, {
      onEnter: function (args) {
        this.label = componentLabel(args[0]);
      },
      onLeave: function () {
        log('PRESS', this.label, '(UnityEngine.UI.Button)');
      }
    });
    console.log('[BTN] hook Button.Press @ ' + pressAddr);
  }
}

function hookClickListener() {
  // 5. ClickListener.Click — dispatch após validação interna
  const clickAddr = addr(RVA.ClickListener_Click);
  if (clickAddr) {
    Interceptor.attach(clickAddr, {
      onEnter: function (args) {
        this.label = componentLabel(args[0]);
      },
      onLeave: function () {
        log('DISPATCH', this.label, '(ClickListener)');
      }
    });
    console.log('[BTN] hook ClickListener.Click @ ' + clickAddr);
  }

  // 6. OnlyClickListener.Click
  const onlyAddr = addr(RVA.OnlyClickListener_Click);
  if (onlyAddr) {
    Interceptor.attach(onlyAddr, {
      onEnter: function (args) {
        this.label = componentLabel(args[0]);
      },
      onLeave: function () {
        log('DISPATCH', this.label, '(OnlyClickListener)');
      }
    });
    console.log('[BTN] hook OnlyClickListener.Click @ ' + onlyAddr);
  }
}

// ── aguarda libil2cpp carregar e hookeia ──────────────────────────────────────

function main() {
  console.log('[BTN] ' + VERSION);

  const poll = setInterval(function () {
    if (!getBase()) return;
    clearInterval(poll);

    console.log('[BTN] libil2cpp.so detectada @ ' + il2cppBase);
    hookButtonEx();
    hookButtonBase();
    hookClickListener();
    console.log('[BTN] todos os hooks ativos. Interaja com os botões do jogo.\n');
  }, 300);

  // Sumário periódico
  setInterval(function () {
    console.log('[BTN] eventos capturados: ' + evtN);
  }, 30000);
}

main();
