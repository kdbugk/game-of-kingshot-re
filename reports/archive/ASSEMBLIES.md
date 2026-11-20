# Assemblies IL2CPP — com.run.tower.defense v1.9.5

> Dump gerado via Frida + `il2cpp_api_dump.js` em runtime.
> Total: **79 assemblies**, **10.997 classes**, **85.847 métodos**.

---

## Jogo e lógica principal

| Assembly | Classes | Métodos | Descrição |
|----------|---------|---------|-----------|
| `Assembly-CSharp.dll` | 3.513 | 32.917 | Toda a lógica do jogo (C# transpilado para IL2CPP). Inclui Lua bindings (XLua/LuaInterface), wrappers de SDK, sistemas de jogo. |
| `Assembly-CSharp-firstpass.dll` | 20 | 86 | Plugins e SDKs de terceiros compilados como "firstpass". Contém `NetEase.NetSecProtect`, `NetEase.HTProtectConfig`, `NetEase.SafeCommResult`, `NetEase.AntiCheatResult`. |

---

## Unity Engine

| Assembly | Classes | Métodos | Descrição |
|----------|---------|---------|-----------|
| `UnityEngine.dll` | 1 | 0 | Stub de entrada do engine |
| `UnityEngine.CoreModule.dll` | 782 | 5.465 | Core do engine: `GameObject`, `Transform`, `MonoBehaviour`, `Time`, `Screen`, `Application`, etc. |
| `UnityEngine.UIElementsModule.dll` | 1.092 | 7.485 | UI Toolkit (novo sistema de UI baseado em UXML/USS) |
| `UnityEngine.UI.dll` | 187 | 1.810 | UGUI (sistema de UI legado: `Canvas`, `Image`, `Text`, `Button`) |
| `UnityEngine.IMGUIModule.dll` | 45 | 582 | GUI imediato (IMGUI legado — `OnGUI`) |
| `UnityEngine.AnimationModule.dll` | 58 | 568 | Sistema de animação: `Animator`, `AnimationClip`, `AnimationCurve` |
| `UnityEngine.AudioModule.dll` | 21 | 168 | Sistema de áudio: `AudioSource`, `AudioClip`, `AudioMixer` |
| `UnityEngine.PhysicsModule.dll` | 31 | 553 | Física 3D: `Rigidbody`, `Collider`, `Physics` |
| `UnityEngine.Physics2DModule.dll` | 30 | 710 | Física 2D: `Rigidbody2D`, `Collider2D` |
| `UnityEngine.ParticleSystemModule.dll` | 61 | 363 | Sistema de partículas |
| `UnityEngine.TextCoreTextEngineModule.dll` | 68 | 467 | Text Core (TextMeshPro engine) |
| `UnityEngine.TextCoreFontEngineModule.dll` | 24 | 115 | Font engine do Text Core |
| `UnityEngine.TextRenderingModule.dll` | 16 | 102 | Renderização de texto legado |
| `UnityEngine.InputLegacyModule.dll` | 17 | 138 | Input legado (`Input.GetKey`, `Input.GetAxis`) |
| `UnityEngine.AndroidJNIModule.dll` | 26 | 523 | Bridge JNI: `AndroidJavaObject`, `AndroidJavaClass`, `AndroidJNI` |
| `UnityEngine.AssetBundleModule.dll` | 7 | 71 | AssetBundles: carregamento dinâmico de assets |
| `UnityEngine.VideoModule.dll` | 16 | 125 | Reprodução de vídeo: `VideoPlayer` |
| `UnityEngine.UnityWebRequestModule.dll` | 19 | 221 | `UnityWebRequest` — HTTP nativo do engine |
| `UnityEngine.UnityWebRequestWWWModule.dll` | 3 | 42 | WWW legado (deprecado) |
| `UnityEngine.UnityWebRequestAssetBundleModule.dll` | 3 | 8 | Download de AssetBundles via UnityWebRequest |
| `UnityEngine.UnityWebRequestTextureModule.dll` | 2 | 7 | Download de texturas via UnityWebRequest |
| `UnityEngine.JSONSerializeModule.dll` | 2 | 6 | `JsonUtility` (serialização JSON nativa) |
| `UnityEngine.PropertiesModule.dll` | 104 | 266 | Properties system (UI Toolkit internals) |
| `UnityEngine.SharedInternalsModule.dll` | 5 | 10 | Internos compartilhados do engine |
| `UnityEngine.SpriteMaskModule.dll` | 2 | 19 | `SpriteMask` |
| `UnityEngine.ImageConversionModule.dll` | 2 | 8 | Conversão de texturas para PNG/JPG |
| `UnityEngine.DirectorModule.dll` | 2 | 61 | Playables Director (Timeline runtime) |
| `UnityEngine.ClothModule.dll` | 4 | 67 | Simulação de tecido (Cloth) |
| `UnityEngine.TilemapModule.dll` | 3 | 0 | Tilemaps 2D |
| `UnityEngine.GridModule.dll` | 2 | 0 | Grid 2D |
| `UnityEngine.SpriteShapeModule.dll` | 2 | 0 | Sprite Shape (paths 2D) |
| `Unity.Timeline.dll` | 89 | 691 | Timeline editor/runtime: cinemática e sequências animadas |
| `Unity.Burst.dll` | 51 | 180 | Burst Compiler: jobs de alto desempenho |
| `Unity.Mathematics.dll` | 10 | 76 | Matemática SIMD (`float3`, `float4x4`, etc.) |
| `Unity.MemoryProfiler.dll` | 9 | 8 | Memory Profiler |
| `Unity.Profiling.Core.dll` | 2 | 3 | Profiler markers |
| `Unity.Notifications.Android.dll` | 20 | 159 | Notificações push locais Android |

---

## .NET / Mono Runtime

| Assembly | Classes | Métodos | Descrição |
|----------|---------|---------|-----------|
| `mscorlib.dll` | 1.283 | 9.752 | Base do .NET: `String`, `List<T>`, `Dictionary`, `Thread`, `Task`, `Reflection`, `IO`, etc. |
| `System.dll` | 507 | 2.970 | Extensões do .NET: `Regex`, `Uri`, `NetworkStream`, `WebClient`, sockets |
| `System.Core.dll` | 46 | 337 | LINQ, expressões lambda, `HashSet<T>` |
| `System.Numerics.dll` | 10 | 74 | `Vector2/3/4`, `Matrix4x4` (SIMD .NET) |
| `System.IO.Compression.dll` | 15 | 80 | `GZipStream`, `DeflateStream`, `ZipArchive` |
| `Mono.Security.dll` | 76 | 437 | Criptografia Mono: X.509, ASN.1, BigInteger, Authenticode |

---

## Rede / HTTP

| Assembly | Classes | Métodos | Descrição |
|----------|---------|---------|-----------|
| `com.Tivadar.Best.HTTP.dll` | 1.235 | 9.106 | **Best HTTP Pro** — biblioteca HTTP/HTTPS de terceiros. Inclui TLS via BouncyCastle (TLS 1.3), HTTP/2, WebSocket, SSE. Substitui `UnityWebRequest` com mais controle. Contém `FrameworkTLSSettings.DefaultCertificationValidator` (ver SECURITY_FINDINGS). |

---

## SDK de Segurança / Anti-cheat (NetEase MobSec)

Presente em `Assembly-CSharp-firstpass.dll` (ver detalhes em SECURITY_FINDINGS.md) e em libs nativas:

| Lib nativa | Tamanho | Papel |
|------------|---------|-------|
| `libnesec.so` | ~1,1 MB | Monitoramento de processo, TracerPid, RASP |
| `libNetHTProtect.so` | ~4,9 MB | Criptografia de comunicação, fingerprint |
| `libxt_a64.so` | ~243 KB | PLT hooking (namespace isolado, invisível ao Frida) |

---

## SDK da Desenvolvedora (CenturyGame / `Unity.dd.sdk.*`)

| Assembly | Classes | Métodos | Descrição |
|----------|---------|---------|-----------|
| `Unity.dd.sdk.scripts.core.dll` | 22 | 151 | Core do SDK próprio: `CGSdk`, `GameUserData`, `CGDataChannelType` |
| `Unity.dd.sdk.scripts.account.dll` | 43 | 348 | Gestão de conta: login, perfil, autenticação |
| `Unity.dd.sdk.scripts.payment.dll` | 42 | 341 | Pagamentos: `CGPayment`, `CGProduct`, `CGSubscriptProduct`. Integra Adyen (`CGAdyenPayAndroid`) e Amazon IAP (`CGAmazonIapAndroid`) |
| `Unity.dd.sdk.scripts.advertising.dll` | 12 | 176 | Anúncios |
| `Unity.dd.sdk.scripts.facebook.dll` | 10 | 109 | Integração Facebook |
| `Unity.dd.sdk.scripts.adjust.dll` | 13 | 65 | Adjust (atribuição de instalação / analytics) |
| `Unity.dd.sdk.scripts.firebase.dll` | 4 | 14 | Firebase wrapper |
| `Unity.dd.sdk.scripts.push.dll` | 8 | 47 | Push notifications |
| `Unity.dd.sdk.scripts.rate.dll` | 7 | 35 | In-app review / rating |
| `Unity.dd.sdk.scripts.survey.dll` | 7 | 24 | Pesquisas in-app |
| `Unity.dd.sdk.scripts.helpshift.dll` | 8 | 42 | Helpshift (suporte ao usuário) |
| `Unity.dd.sdk.scripts.tga.dll` | 6 | 20 | TGA (analytics interno?) |
| `Unity.dd.sdk.scripts.twitter.dll` | 7 | 22 | Integração Twitter/X |
| `Unity.dd.sdk.scripts.compliancesuite.dll` | 22 | 74 | Compliance: GDPR, COPPA, consentimento |
| `Unity.dd.sdk.scripts.tools.dll` | 47 | 423 | Utilitários internos do SDK |

---

## Firebase

| Assembly | Classes | Métodos | Descrição |
|----------|---------|---------|-----------|
| `Firebase.App.dll` | 25 | 169 | Firebase core: inicialização, configuração |
| `Firebase.Crashlytics.dll` | 27 | 150 | Firebase Crashlytics: crash reporting automático |
| `Firebase.Platform.dll` | 39 | 131 | Platform abstraction layer do Firebase |

---

## Serialização / Compressão

| Assembly | Classes | Métodos | Descrição |
|----------|---------|---------|-----------|
| `OdinSerializer.dll` | 215 | 1.102 | Odin Serializer (Sirenix) — serialização binária/JSON de alta performance para Unity |
| `Pathfinding.Ionic.Zip.Reduced.dll` | 81 | 524 | DotNetZip reduzido — leitura/escrita de arquivos ZIP |
| `CString.dll` | 15 | 119 | Strings comprimidas/otimizadas (provavelmente Lua strings) |

---

## Pathfinding / AI

| Assembly | Classes | Métodos | Descrição |
|----------|---------|---------|-----------|
| `AstarPathfindingProject.dll` | 205 | 1.515 | A* Pathfinding Project Pro — navegação e busca de caminhos |
| `PathCreator.dll` | 16 | 73 | Path Creator — criação de caminhos Bezier no editor |

---

## UI / Animação

| Assembly | Classes | Métodos | Descrição |
|----------|---------|---------|-----------|
| `DOTween.dll` | 107 | 420 | DOTween Pro — sistema de tweening/animação de propriedades |
| `spine-unity.dll` | 161 | 951 | Spine — animação esqueletal 2D (Esoteric Software) |

---

## Áudio

| Assembly | Classes | Métodos | Descrição |
|----------|---------|---------|-----------|
| `CriMw.CriWare.Runtime.dll` | 192 | 1.323 | CRI Middleware — ADX2/Sofdec2: áudio e vídeo profissional (comum em jogos japoneses/asiáticos) |

---

## Entitas (ECS)

| Assembly | Classes | Métodos | Descrição |
|----------|---------|---------|-----------|
| `Entitas.dll` | 65 | 264 | Entitas — Entity Component System para Unity |
| `Entitas.CodeGeneration.Attributes.dll` | 3 | 2 | Atributos de geração de código do Entitas |

---

## Hotpatch

| Assembly | Classes | Métodos | Descrição |
|----------|---------|---------|-----------|
| `IFix.Core.dll` | 41 | 192 | IFix (Tencent) — sistema de hotpatch C# em runtime via VM própria. Presente no APK mas **inativo em runtime** (nenhum patch carregado — confirmado via Frida). |

---

## Utilitários internos / gerados

| Assembly | Classes | Métodos | Descrição |
|----------|---------|---------|-----------|
| `DesperateDevs.Utils.dll` | 2 | 3 | Utilitários DesperateDevs (framework ECS) |
| `Debugger.dll` | 5 | 27 | Logger/debugger interno do jogo |
| `__Generated` | 5 | 3 | Código gerado automaticamente (provavelmente pelo Entitas ou XLua) |
