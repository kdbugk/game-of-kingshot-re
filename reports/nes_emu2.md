# RELATORIO_EMU2 — lane EMU-FINISH (emu_unpack_nesec.py, Unicorn ARM64)

## Resultado curto
- Os **3 inicializadores (.init_array 0xed534, 0xed5e4, 0xedd38) agora completam sem UcError e sem timeout** (~14 s).
- **Mas a imagem praticamente não muda**: 1 único byte difere (`0x1039e1`: 0x40→0x50, em bloco 4KB 0x103000). Strings no fragmento 0–0xd8000: **638 → 638**. Nenhuma região nova abriu. `nesec_image2.bin` foi salvo, mas é ≈ idêntico a `nesec_image.bin` (backup do original: `nesec_image_before.bin`).
- Meta @0x103560: `+0x8c=0x6f6e25d3, +0x90=0x1ba1e27e, +0x94=0x5188f8eb, +0x98=0x2897ce79, +0x9c=0x62bed4ec` — **igual antes/depois**; NÃO é 5. Provavelmente o campo é guardado ofuscado (a leitura crua não é o valor lógico) ou é preenchido por etapa posterior (ver "Próximos passos"). Não afirmo qual das duas.

## O que foi implementado
1. **dladdr real**: endereço dentro da imagem (0..0x110000) → preenche Dl_info {fname*, 0,0,0} com `/data/app/com.run.tower.defense/libnesec.so` (string no heap) e retorna 1. Endereço de trampolim (= "libc") → fname `/apex/com.android.runtime/lib64/bionic/libc.so` (o packer faz `strstr(fname,"libc.so")` etc. — o log mostra `strstr(..."libc.so") → 39`). Fora disso retorna 0.
2. **dl_iterate_phdr real**: copia os phdrs do próprio ELF para o heap, monta `dl_phdr_info {addr=0, name*, phdr*, phnum}` e chama o callback x0 com (info, 32, data=x1) por redirecionamento de PC (LR → trampolim 0x…ffe0 que restaura o LR original e devolve o retorno do callback). **Implementado mas NÃO exercitado** — nenhum caminho chamou dl_iterate_phdr nesta execução (log sem `[dl_iterate_phdr]`).
3. **CATCHALL**: agora loga x0-x2 + LR, só as 3 primeiras ocorrências por LR (antes: 7 M linhas), contador por LR no fim, retorna 0 e volta ao LR.
4. Novos stubs: `strstr` (real), `strcpy`, `strcspn`, `basename`, `atoi`, `readlink`, `sprintf/snprintf` (só copia o formato, sem formatação — logado), `stat/fstat`=-1, `strtok`=0.
5. Diagnóstico: ring-buffer das últimas 20 instruções + capstone + regs ao ocorrer UcError/timeout (`[ring]`); timeout configurável por env `EMU_TIMEOUT` (padrão 60 s); detecção de parada por timeout (PC≠STOP).

## ACHADO principal (a causa do "ctor3 morre")
O problema real não era só dladdr: o resolvedor em 0xf3b38–0xf4110 chama `dlsym(RTLD_DEFAULT, nome)` com **nomes cifrados/lixo** (janela deslizante sobre um blob ofuscado). O stub antigo devolvia o CATCHALL (não-NULL) para qualquer nome desconhecido ⇒ o packer "resolvia" cada símbolo, gravava o ponteiro do CATCHALL em slots de GOT (ex.: 0xdd8e0, usado pelo PLT 0xd3fe0) e ficava preso num **loop infinito em 0x64900–0x64938** (`bl 0xd3fe0` → CATCHALL x0=0 → `b.ne`; 2.3 M iterações em 60 s). Com um `dlsym` realista — **NULL para nome que não é identificador C** — o resolvedor desiste rápido e ctor3 retorna. (Log antes: `run_emu2_dlsym_catchall.log`; depois: `run_emu2_final.log`.)
Ou seja: ao concertar o dlsym, o ctor3 termina, mas termina por **caminho de falha do dlsym** (nome cifrado ≠ símbolo real), por isso nada novo é construído.

## Diff da imagem (sha256 por bloco de 4KB, antes × depois)
- Blocos alterados: apenas `0x103000` (1 byte em 0x1039e1: 0x40→0x50). Resto idêntico. Tamanho 1 132 824 B nos dois.
- Strings (≥10 chars, 0–0xd8000): 638 → 638.

## Estado / honestidade
- **Meta == 5 NÃO confirmado**; nenhuma etapa extra rodou depois do ctor3. O gate-byte 0x103581 já vale 1 (one-shot já consumido) e o ctor3 sai pelo ramo curto.
- Nomes que chegam ao dlsym são cifrados: ou há uma função de decifra (`bl 0xeffb0` produz std::string a partir de blobs em 0x102010-0x102070, usada ao redor do strstr "libc.so"; a decifra dos nomes do dlsym provavelmente é feita por outro ponto que não foi atingido), ou o caminho que decifra depende de algo ainda stubado (`__system_property_get` ainda cai no CATCHALL via dlsym — 1 ocorrência, lr=0xf501c; `atoi` agora real).
- Não escrevi no repo. Arquivos auxiliares: `disasm_tool.py` (capstone helper: `python3 disasm_tool.py <ini_hex> <fim_hex>` no WSL), logs `run_emu2_*.log`, `emu_unpack_nesec.py.bak` (versão anterior).

## Próximos passos (honestos)
1. Descobrir quem decifra os nomes passados ao dlsym (entender 0xeffb0 e o blob 0x102010–0x102070; decompilar 0xf3b38/0xf48a8/0xf501c no Ghidra com a imagem já dumpada). Se a decifra é um XOR rolante, aplicar manualmente e ver quais símbolos reais o packer procura (provável: hooks/anti-debug libc).
2. Tratar `__system_property_get` (dlsym "ok" → impl real devolvendo string vazia/ro.* plausível) e re-rodar para ver se o ctor3 segue o ramo longo.
3. Exercitar dl_iterate_phdr: só será chamado em etapa pós-ctor (talvez via JNI_OnLoad/outra exportação) — fora dos .init_array. Rodar símbolos exportados (JNI_OnLoad etc.) no emulador.
4. Considerar que a "meta" é lida com transformação (opaque predicates em 0xedd4c–0xede90): emular com hook em 0xedd4c pra ver qual ramo vence em vez de ler o valor cru.
