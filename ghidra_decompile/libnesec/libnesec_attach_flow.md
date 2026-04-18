# libnesec - Fluxo de verificacao de attach/debug

Este arquivo resume o fluxo das funcoes mais relevantes encontradas na trilha de verificacao de ambiente do `libnesec`, com pseudocodigo C# de alto nivel.

Funcoes cobertas:

- `FUN_7c2c40b0f8`
- `FUN_7c2c3e2f48`
- `FUN_7c2c3e3494`
- `FUN_7c2c40b018`
- `FUN_7c2c40b090`

## Visao geral do fluxo

```text
FUN_7c2c40b0f8
  -> checa estado inicial do ambiente
  -> abre /proc/self/status
  -> busca e valida pelo menos Seccomp e estado de tracing/debug
  -> tenta localizar linker64 / libnativebridge.so
  -> registra callbacks relacionados a dlopen/linker
      -> FUN_7c2c40b018
      -> FUN_7c2c40b090

FUN_7c2c3e3494
  -> enumera threads via /proc/<pid>/task/<tid>/status
  -> busca linha TracerPid:
  -> parseia o PID do tracer
  -> compara contra valores permitidos
  -> marca estado e aciona tratamento quando encontra tracer inesperado
  -> tambem observa threads em estado (zombie)

FUN_7c2c3e2f48
  -> helper pequeno de normalizacao/preparacao da string TracerPid:\t0

FUN_7c2c40b018 / FUN_7c2c40b090
  -> callbacks/wrappers ligados ao monitoramento de linker/dlopen
```

## 1. FUN_7c2c40b0f8

### Fluxo

1. Chama `FUN_7c2c42554c()` para obter um estado inicial.
2. Se o estado for maior que `2`, marca `DAT_7c2c43b87e = 1`.
3. Executa uma checagem preliminar com `thunk_EXT_FUN_7f2caaeba0(0x27, 0)`.
4. Se essa checagem preliminar falhar, abre `"/proc/self/status"`.
5. Itera pelas linhas do arquivo ate satisfazer duas condicoes:
   - `Seccomp == 2`
   - outro estado interno associado ao parse de tracing/debug igual a `1`
6. Se a leitura falhar ou as condicoes nao forem satisfeitas no fluxo esperado, avalia `libnativebridge.so`.
7. Localiza `linker64` e tenta resolver simbolos ligados a `dlopen`.
8. Se conseguir, instala callbacks:
   - `FUN_7c2c40b018`
   - `FUN_7c2c40b090`
9. No final, agenda/aciona `FUN_7c2c40adc8(...)`.

### Pseudocodigo C#

```csharp
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

public static class LibnesecEnvironmentCheck
{
    private static bool GlobalInitFlag;
    private static IntPtr DlopenCallbackA;
    private static IntPtr DlopenCallbackB;

    public static void RunEnvironmentChecks(object context)
    {
        int initialState = GetInitialState();
        bool stateIsTwo = initialState == 2;

        if (initialState >= 2)
        {
            if (!stateIsTwo)
                GlobalInitFlag = true;

            bool fastPathOk = CheckEnvironmentFastPath(0x27, 0);

            if (fastPathOk)
            {
                MarkFastPathOk();
            }
            else
            {
                bool seccompOk = false;
                bool traceStateOk = false;

                using StreamReader? reader = OpenProcSelfStatus();
                if (reader != null)
                {
                    while (!reader.EndOfStream)
                    {
                        string? line = reader.ReadLine();
                        if (line == null)
                            break;

                        if (line.Contains("Seccomp:"))
                        {
                            seccompOk = ParseSeccomp(line) == 2;
                        }
                        else if (LooksLikeTraceStateLine(line))
                        {
                            traceStateOk = ParseTraceState(line) == 1;
                        }

                        if (seccompOk && traceStateOk)
                            break;
                    }
                }

                if (!CheckNativeBridgeError())
                {
                    CheckNativeBridgeLibrary();
                }
            }

            RegisterDlopenHooksIfPossible();
        }

        ScheduleFinalEnvironmentAction(context);
    }

    private static int GetInitialState() => 2;
    private static bool CheckEnvironmentFastPath(int code, int value) => false;
    private static void MarkFastPathOk() { }
    private static StreamReader? OpenProcSelfStatus()
    {
        const string path = "/proc/self/status";
        return File.Exists(path) ? new StreamReader(path) : null;
    }
    private static int ParseSeccomp(string line) => line.Trim().EndsWith("2") ? 2 : -1;
    private static bool LooksLikeTraceStateLine(string line) =>
        line.StartsWith("TracerPid:") || line.Contains("trace");
    private static int ParseTraceState(string line) => line.Trim().EndsWith("0") ? 1 : 0;
    private static bool CheckNativeBridgeError() => false;
    private static void CheckNativeBridgeLibrary() { }

    private static void RegisterDlopenHooksIfPossible()
    {
        bool linkerFound = FindLinker64();
        bool dlopenResolved = ResolveDlopenSymbols();

        if (linkerFound && dlopenResolved)
        {
            DlopenCallbackA = RegisterCallback(DlopenProbeA);
            DlopenCallbackB = RegisterCallback(DlopenProbeB);
        }
    }

    private static bool FindLinker64() => true;
    private static bool ResolveDlopenSymbols() => true;
    private static IntPtr RegisterCallback(Delegate d) => IntPtr.Zero;
    private static ulong DlopenProbeA() => 0;
    private static ulong DlopenProbeB() => 0;
    private static void ScheduleFinalEnvironmentAction(object context) { }
}
```

## 2. FUN_7c2c3e2f48

### Fluxo

1. Recebe um buffer e um tamanho.
2. Se o tamanho for maior que `0xb`, escreve `0` no ultimo byte util para testar/manipular a string.
3. Faz uma checagem auxiliar.
4. Se a checagem for positiva, sobrescreve o inicio do buffer com `"TracerPid:\t0"`.
5. Caso contrario, restaura o byte original.

### Pseudocodigo C#

```csharp
public static class TracerPidKeyNormalizer
{
    public static void NormalizeTracerPidPattern(byte[] buffer, int length)
    {
        if (buffer == null || length <= 0 || length > buffer.Length)
            return;

        if (length <= 0x0B)
            return;

        int lastIndex = length - 1;
        byte original = buffer[lastIndex];
        buffer[lastIndex] = 0;

        if (InternalCheck())
        {
            byte[] pattern = System.Text.Encoding.ASCII.GetBytes("TracerPid:\t0");
            Array.Copy(pattern, 0, buffer, 0, Math.Min(pattern.Length, buffer.Length));
        }
        else
        {
            buffer[lastIndex] = original;
        }
    }

    private static bool InternalCheck() => true;
}
```

## 3. FUN_7c2c3e3494

### Fluxo

1. Obtem o PID atual.
2. Enumera TIDs do processo.
3. Para cada thread:
   - monta `"/proc/<pid>/task/<tid>/status"`
   - abre e le o arquivo
4. Para cada linha lida:
   - se contiver `"TracerPid:"`, parseia o valor numerico
   - compara com dois PIDs permitidos
   - se o PID do tracer for diferente dos permitidos, aciona tratamento
   - se a linha contiver `"(zombie)"`, marca uma flag e aciona outro tratamento
5. Fecha o reader e continua para a proxima thread.

### Observacao

Essa funcao e o melhor candidato para a verificacao real de attach/debug por thread. O diferencial aqui e que ela nao olha apenas `/proc/self/status`, mas tambem `/proc/<pid>/task/<tid>/status`.

### Pseudocodigo C#

```csharp
public static class ThreadTracerPidScanner
{
    private static int AllowedTracerPidA;
    private static bool ZombieThreadSeen;

    public static void ScanThreadStatusAndTracerPid(int currentPid)
    {
        foreach (int tid in EnumerateThreadIds(currentPid))
        {
            string statusPath = $"/proc/{currentPid}/task/{tid}/status";
            if (!File.Exists(statusPath))
                continue;

            using StreamReader reader = new StreamReader(statusPath);
            int iterationCount = 0;

            while (!reader.EndOfStream)
            {
                string? line = reader.ReadLine();
                if (line == null)
                    break;

                if (line.Contains("TracerPid:"))
                {
                    int tracerPid = ParseTracerPid(line);
                    int allowedTracerPidB = GetSecondaryAllowedTracerPid();

                    bool unexpectedTracer =
                        tracerPid != 0 &&
                        tracerPid != AllowedTracerPidA &&
                        tracerPid != allowedTracerPidB;

                    if (unexpectedTracer)
                    {
                        MarkUnexpectedTracer(currentPid);
                        HandleUnexpectedTracer(currentPid, tid, tracerPid);
                    }
                }
                else if (line.Contains("(zombie)"))
                {
                    ZombieThreadSeen = true;
                    NotifyZombieThread(currentPid, tid);
                    HandleZombieThread(currentPid, tid);
                }

                iterationCount++;
                if (iterationCount == 2)
                    break;
            }
        }
    }

    private static IEnumerable<int> EnumerateThreadIds(int pid)
    {
        string taskDir = $"/proc/{pid}/task";
        if (!Directory.Exists(taskDir))
            return Array.Empty<int>();

        return Directory
            .GetDirectories(taskDir)
            .Select(Path.GetFileName)
            .Where(name => int.TryParse(name, out _))
            .Select(int.Parse);
    }

    private static int ParseTracerPid(string line)
    {
        int sep = line.IndexOf(':');
        if (sep < 0)
            return -1;

        string text = line.Substring(sep + 1).Trim();
        return int.TryParse(text, out int value) ? value : -1;
    }

    private static int GetSecondaryAllowedTracerPid()
    {
        return Environment.ProcessId;
    }

    private static void MarkUnexpectedTracer(int currentPid) { }
    private static void HandleUnexpectedTracer(int pid, int tid, int tracerPid) { }
    private static void NotifyZombieThread(int pid, int tid) { }
    private static void HandleZombieThread(int pid, int tid) { }
}
```

## 4. FUN_7c2c40b018

### Fluxo

1. Chama `FUN_7c2c40a834(...)`.
2. Se o teste passar, chama novamente `FUN_7c2c40a834(...)` com outra origem/contexto.
3. Se tambem passar, executa `FUN_7c2c40ab2c(...)`.
4. Se tudo passar, desvia para callback global `DAT_7c2c43beb0`.

### Interpretacao

Esse wrapper parece ser um callback instalado em torno de eventos de carregamento dinamico, provavelmente ligados a `dlopen`/linker.

### Pseudocodigo C#

```csharp
public static class DlopenProbeA
{
    private static Func<ulong>? GlobalCallback;

    public static ulong Invoke(
        ulong arg1,
        ulong arg2,
        ulong eventContext,
        ulong[] metadata,
        string moduleName,
        int[] flags,
        ulong extra1,
        ulong extra2)
    {
        bool firstCheck = CheckDlopenContext(eventContext, metadata, moduleName, flags, extra1, extra2);
        if (!firstCheck)
            return 0;

        bool secondCheck = CheckDlopenContext(eventContext, metadata, moduleName, flags, extra1, extra2);
        if (!secondCheck)
            return 0;

        bool finalCheck = ValidateDlopenEvent(arg1, arg2, eventContext, metadata, moduleName, flags, extra1, extra2);
        if (!finalCheck)
            return 0;

        return GlobalCallback != null ? GlobalCallback() : 0;
    }

    private static bool CheckDlopenContext(
        ulong eventContext,
        ulong[] metadata,
        string moduleName,
        int[] flags,
        ulong extra1,
        ulong extra2) => true;

    private static bool ValidateDlopenEvent(
        ulong arg1,
        ulong arg2,
        ulong eventContext,
        ulong[] metadata,
        string moduleName,
        int[] flags,
        ulong extra1,
        ulong extra2) => true;
}
```

## 5. FUN_7c2c40b090

### Fluxo

1. Faz verificacao inicial com `FUN_7c2c40a834(...)`.
2. Faz nova verificacao com contexto diferente.
3. Chama `FUN_7c2c40ab2c(...)`.
4. Se tudo passar, desvia para callback global `DAT_7c2c43beb8`.

### Interpretacao

E o par de `FUN_7c2c40b018`. A estrutura e quase igual, mudando apenas o contexto inicial e o callback final.

### Pseudocodigo C#

```csharp
public static class DlopenProbeB
{
    private static Func<ulong>? GlobalCallback;

    public static ulong Invoke(
        ulong arg1,
        ulong arg2,
        ulong eventContext,
        ulong[] metadata,
        string moduleName,
        int[] flags,
        ulong extra1,
        ulong extra2)
    {
        bool firstCheck = CheckDlopenContextVariant(eventContext, metadata, moduleName, flags, extra1, extra2);
        if (!firstCheck)
            return 0;

        bool secondCheck = CheckDlopenContextVariant(eventContext, metadata, moduleName, flags, extra1, extra2);
        if (!secondCheck)
            return 0;

        bool finalCheck = ValidateDlopenEvent(arg1, arg2, eventContext, metadata, moduleName, flags, extra1, extra2);
        if (!finalCheck)
            return 0;

        return GlobalCallback != null ? GlobalCallback() : 0;
    }

    private static bool CheckDlopenContextVariant(
        ulong eventContext,
        ulong[] metadata,
        string moduleName,
        int[] flags,
        ulong extra1,
        ulong extra2) => true;

    private static bool ValidateDlopenEvent(
        ulong arg1,
        ulong arg2,
        ulong eventContext,
        ulong[] metadata,
        string moduleName,
        int[] flags,
        ulong extra1,
        ulong extra2) => true;
}
```

## Conclusao tecnica

O fluxo observado aponta para tres camadas diferentes:

1. Validacao de ambiente via `/proc/self/status`
2. Verificacao de `TracerPid` por thread em `/proc/<pid>/task/<tid>/status`
3. Monitoramento de carga dinamica por `linker64`/`dlopen`

O ponto mais forte para entender a deteccao de attach/debug e `FUN_7c2c3e3494`, porque ela faz parse direto de `TracerPid:` nas threads.
