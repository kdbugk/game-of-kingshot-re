# 📄 Análise Estática — libNetHTProtect.so

## 📌 Visão Geral

Este documento descreve o fluxo interno da biblioteca **libNetHTProtect.so**, incluindo:

- Pipeline de processamento (coleta → serialização → digest)
- Funções principais identificadas
- Interface externa (vtable)
- Entry points reais
- Integração com runtime (IL2CPP / JNI)

---

## 🧠 Arquitetura Geral

```
IL2CPP / Java
    ↓
oOOoo0Oo0000000O (EntryPoint externo)
    ↓
FUN_0033d5a0 (Engine)
    ↓
FUN_0019ed9c / FUN_001ca50c
    ↓
FUN_0033acfc (Marshal)
    ↓
Interface externa (vtable)
```

---

## 🔥 Engine Central

### FUN_0033d5a0

Responsável por:
- Validar parâmetros
- Checar estado global
- Escolher pipeline

```c
if ((param_8 & 1) == 0)
    FUN_0019ed9c(...);
else
    FUN_001ca50c(...);
```

---

## 🧩 Pipeline

### FUN_0019ed9c
- Coleta dados do sistema
- Constrói fingerprint
- Processa memória

### FUN_001ca50c
- Executa digest direto
- Calcula hash/checksum

---

## 📦 Serialização

### FUN_002ac050
- Encoding estruturado
- Estilo varint
- Serialização de campos

---

## 🧠 Coleta de Memória

### FUN_002d23f8
- Lê /proc/self/maps
- Retorna permissões de memória

---

## 🧩 Interface Externa (CRÍTICO)

### param_1 = objeto com vtable

Assembly observado:

```
ldr x8, [x19]
ldr x8, [x8, #0x558]
blr x8
```

Estrutura:

```c
struct Obj {
    void **vtable;
};
```

### Slots utilizados

- 0x558 → input
- 0x5c0 → pointer
- 0x600 → release
- 0x580 → alloc
- 0x680 → write

---

## 📤 Marshaling

### FUN_0033acfc

```c
result = engine(...);

if (result >= 0) {
    write(status);
    write(payload);
} else {
    write(error);
}
```

---

## 🚀 Entry Point

### oOOoo0Oo0000000O

- Função externa (EXTERNAL)
- Chamada via JNI / IL2CPP

Fluxo:

```
C# / Java
    ↓
native call
    ↓
oOOoo0Oo0000000O
    ↓
engine interna
```

---

## 🧠 Conclusão

- A biblioteca executa processamento
- A decisão final NÃO está nela
- O runtime externo decide o resultado

---

## 🚀 Próximos Passos

1. Identificar implementação da vtable
2. Analisar chamadas IL2CPP
3. Rastrear uso do resultado
