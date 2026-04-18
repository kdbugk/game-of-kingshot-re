# Descobertas de Segurança — com.run.tower.defense v1.9.5

> **Contexto:** exercício educacional de engenharia reversa Android.
> App: jogo Unity/IL2CPP. Runtime: ARM64, Android 11.
> Ferramentas: Frida 16.x (spawn mode), Ghidra (base 0x100000), dump IL2CPP completo.

---

## 1. Strings hardcoded ofuscadas em `NetSecProtect`

**Arquivo:** `Assembly-CSharp-firstpass.dll` → `NetEase.NetSecProtect`
**Método relevante:** `initDecrypt(String cipherText)` — RVA `0x19e1c2c` / Ghidra `0x1ae1c2c`

### O padrão

A classe `NetSecProtect` declara 10 pares de campos estáticos:

```csharp
private static String strUUU_0;   // cifrado (hardcoded no binário)
private static String strCCC_0;
private static String strHHH_0;
private static String strIII_0;
private static String strJJ0_0 .. strJJ7_0;

private static String strUUU;     // decifrado em runtime pelo initDecrypt()
private static String strCCC;
private static String strHHH;
private static String strIII;
private static String strJJ0 .. strJJ7;
```

Os valores `_0` são strings cifradas embutidas no binário. Na inicialização, `initDecrypt()` as decifra e popula os campos sem sufixo. Os nomes sugerem:

| Campo     | Conteúdo provável          |
|-----------|---------------------------|
| `strUUU`  | URL do servidor de segurança |
| `strCCC`  | Channel (canal/loja)      |
| `strHHH`  | Host alternativo          |
| `strIII`  | Product/Game ID           |
| `strJJ0..7` | JNI method names ou config extra |

### Como explorar

Hookear `initDecrypt` em libil2cpp.so (função C# pura, não monitorada pelo libnesec):

```javascript
// Ghidra 0x1ae1c2c → offset = 0x19e1c2c
const il2cpp = Process.findModuleByName('libil2cpp.so');
Interceptor.attach(il2cpp.base.add(0x19e1c2c), {
  onEnter(args) { this.cipher = args[1]; },      // String gerenciada
  onLeave(retval) {
    // ler String IL2CPP: len @ +0x10, chars @ +0x14
    const cipher = readIL2CppString(this.cipher);
    const plain  = readIL2CppString(retval);
    console.log('initDecrypt: "' + cipher + '" → "' + plain + '"');
  }
});
```

**Impacto:** revela o productId, gameKey, host e channel do SDK NetEase em texto claro, sem precisar quebrar a cifra.

---

## 2. `HTProtectConfig.initThread` — flag que controla o daemon do libnesec

**Arquivo:** `Assembly-CSharp-firstpass.dll` → `NetEase.HTProtectConfig`

```csharp
private Boolean initThread;       // inicia a thread de monitoramento?
private Boolean initThreadExit;   // a thread encerra o processo ao detectar?
private Boolean initThreadCrash;  // a thread crasheia o processo ao detectar?
private Int32   initWaitSecond;   // segundos de espera antes do primeiro check
```

### O que isso significa

Esses flags são passados via `getAndroidConfig()` para o Java/JNI e de lá para o libnesec durante a inicialização. São os parâmetros que controlam o comportamento do SDK anti-cheat:

- `initThread=false` → o nesec provavelmente **não inicia** o loop de `TracerPid` (confirmado no CLAUDE.md: `nesec_loop_tracerpid_A/B` são os loops que detectam Frida)
- `initThreadExit=false` → mesmo que detecte algo, não encerra o processo
- `initThreadCrash=false` → não crasheia

### Fluxo real

```
Lua → NetEase_HTProtectConfigWrap.setInitThread(false)
    → HTProtectConfig.initThread = false
    → NetSecProtect.init() → getAndroidConfig() → AndroidJavaObject
    → JNI → libNetHTProtect.JNI_OnLoad → libnesec init
    → libnesec verifica flag → não inicia nesec_loop_tracerpid_A/B
```

**Impacto:** se um atacante conseguir injetar código antes da chamada a `init()` e modificar o `HTProtectConfig` passado, pode desabilitar todo o monitoramento do libnesec — tornando os hooks de Frida na libNetHTProtect detectáveis (mas sem consequência).

---

## 3. `FrameworkTLSSettings.DefaultCertificationValidator` — potencial MITM

**Arquivo:** `com.Tivadar.Best.HTTP.dll` → `Best.HTTP.Hosts.Settings.FrameworkTLSSettings`

```csharp
// Lambda definida no .cctor():
public Boolean <.cctor>b__6_0(
    String host,
    X509Certificate certificate,
    X509Chain chain,
    SslPolicyErrors sslPolicyErrors  // ← None=0, RemoteCertificateNameMismatch=1,
);                                    //   RemoteCertificateChainErrors=4, etc.
// RVA: 0x269ef4c  Ghidra: 0x279ef4c

protected internal static Func<...> DefaultCertificationValidator;  // ← usa essa lambda
protected internal        Func<...> CertificationValidator;         // ← por host (sobrescreve)
```

### A questão

A biblioteca `Best.HTTP` usa essa lambda para validar **todos** os certificados TLS do jogo. O `DefaultCertificationValidator` é definido no construtor estático da classe.

Se a implementação for:
```csharp
// VULNERÁVEL — aceita qualquer certificado
return true;

// OU
return sslPolicyErrors == SslPolicyErrors.None;
// → mas se não há cert pinning, qualquer CA válida (ou CA própria instalada no dispositivo) passa
```

Para confirmar, analisar no Ghidra o endereço `0x279ef4c`:
- Se retorna `1` (true) incondicionalmente → **MITM trivial** com qualquer certificado
- Se verifica `sslPolicyErrors == 0` → vulnerável a CAs de sistema instaladas pelo usuário (sem cert pinning)
- O jogo **não usa** cert pinning nativo (não foi encontrada nenhuma classe `CertificatePinner` ou similar no dump)

**Impacto:** possível interceptação de todo o tráfego HTTP do jogo com proxy (Burp Suite, mitmproxy) em dispositivos com CA personalizada instalada. O tráfego protegido pelo NetEase SDK (`safeCommToServerV30`) usa uma camada adicional de criptografia e seria criptografado mesmo com MITM TLS.

---

## 4. `safeCommToServerV30` — cliente escolhe algoritmo e nível de proteção

**Arquivo:** `Assembly-CSharp-firstpass.dll` → `NetEase.NetSecProtect`

```csharp
SafeCommResult safeCommToServerV30(
    Int32 version,       // versão do protocolo
    Int32 alg,           // algoritmo de criptografia (cliente escolhe)
    Byte[] inputData,    // payload em claro
    Boolean isCrucial    // "crucial" = proteção mais forte?
);
// RVA: 0x19e6324  Ghidra: 0x1ae6324

// Variantes:
SafeCommResult safeCommToServerByteV30(Int32 version, Int32 alg, Byte[] inputData, Boolean isCrucial);
SafeCommResult htpSign(Int32 version, Int32 alg, Byte[] inputData);  // apenas assinatura
String         safeComm(String inputData, Int32 algType, Boolean dec); // encode/decode
```

### Estrutura do resultado

```csharp
public class SafeCommResult {
    Int32  SC_CODE_OK;             // = 0
    Int32  SC_DATA_TAMPERED;       // dado adulterado detectado pelo servidor
    Int32  SC_DATA_DECRYPT_ERROR;  // falha de descriptografia no servidor
    Int32  SC_PROTOCOL_VERSION_ERROR;
    Int32  ret;                    // código de retorno real
    Byte[] encBytes;               // dados criptografados produzidos
    String encResult;              // resultado como string
    String signResult;             // assinatura/hash
    Byte[] decResult;              // dados decifrados (para fromServer)
}
```

### A questão

O cliente controla `alg` (índice de algoritmo) e `isCrucial`. Se o servidor não valida se o algoritmo escolhido é adequado para o tipo de operação, um cliente modificado pode:
1. Passar `alg=0` (algoritmo nulo ou mais fraco)
2. Enviar `isCrucial=false` em operações que deveriam ser cruciais

O código de retorno `SC_DATA_TAMPERED` indica que o servidor faz alguma verificação, mas não se verifica o nível de proteção esperado.

---

## 5. `localSaveEncode/Decode` — salvar dados locais com chave derivada do dispositivo?

**Arquivo:** `Assembly-CSharp-firstpass.dll` → `NetEase.NetSecProtect`

```csharp
String localSaveEncode(String inputData, Int32 algIndex);   // RVA: 0x19e45a8
String localSaveDecode(String inputData, Int32 algIndex);   // RVA: 0x19e49f8
String localSaveBytesEncode(Byte[] inputData, Int32 algIndex); // RVA: 0x19e4e50
Byte[] localSaveBytesDecode(String inputData, Int32 algIndex); // RVA: 0x19e4f34
```

Essas funções criptografam/decriptografam dados de save local. O parâmetro `algIndex` seleciona o algoritmo. Se a chave usada internamente pelo libNetHTProtect for derivada do `productId` (hardcoded — ver achado #1) e não de algo device-specific, **todos os save files do mesmo jogo terão a mesma chave** e seriam decifráveis off-device.

---

## 6. libnesec — verificação de integridade de código em libNetHTProtect

**Observação experimental (Frida):**

Hookear qualquer função dentro de `libNetHTProtect.so` por offset causa `process-terminated` em ~8-10 segundos. Hookear as mesmas funções após carregar o script sem hooks (baseline) funciona por 60s. Conclusão:

- `libnesec.so` lê os primeiros bytes de funções críticas de `libNetHTProtect.so` e compara com valores esperados (hash ou comparação direta)
- O check ocorre em um loop periódico (~8-10s de latência)
- Funções confirmadas como monitoradas: `engine_central` (offset `0x23d5a0`), possivelmente todas as funções principais
- `JNI_OnLoad` (export) também é monitorado
- O Frida em si **não** é detectado — apenas a modificação de código (trampolines)

Isso é uma implementação de **RASP (Runtime Application Self-Protection)** — a lib protege seu próprio código em tempo de execução.

---

## Resumo

| # | Achado | Impacto | Como explorar |
|---|--------|---------|---------------|
| 1 | Strings hardcoded cifradas | Config do SDK em texto claro | Hook `initDecrypt` em libil2cpp.so |
| 2 | `initThread` flag | Desabilitar anti-cheat via config | Injetar antes de `init()` |
| 3 | `DefaultCertificationValidator` | Potencial MITM TLS | Analisar Ghidra `0x279ef4c`, proxy com CA custom |
| 4 | `alg` / `isCrucial` client-controlled | Downgrade de algoritmo | Modificar chamada `safeCommToServerV30` |
| 5 | `localSave` chave possivelmente estática | Decifrar saves off-device | Hook `localSaveDecode` + checar chave |
| 6 | RASP em libNetHTProtect | Bloqueia hooks diretos | Hookear do lado IL2CPP (libil2cpp.so) |
