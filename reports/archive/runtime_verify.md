# Verificação em runtime (Lane P) — resultado: BLOQUEADO (sem dump runtime)

## O que rodou
- Cópia `dump_runtime.py` (de `dump_final.py`, OUT_DIR → `/home/re/work/apk/il2cpp_dump_114_runtime/`). Telefone via adb OK (192.168.0.77:5555), frida-server reiniciado pelo script.
- **Janela 1 (10 min):** operador não abriu o jogo → `[X] jogo não apareceu`.
- **Janela 2 (10 min):** operador abriu o jogo (pid 14053). O script aguardou 45 s de boot e tentou attach:
  - retry 1: `the connection is closed`
  - retry 2/3: `unable to find process with pid 14053`
  - `tabela não achada`.
- logcat: `Process com.run.tower.defense (pid 14053) has died` às 23:44:10, `Process 14053 exited cleanly (0)` → o jogo **encerrou sozinho (saída limpa, não crash/SIGKILL do sistema)** durante/logo após o attach do frida: comportamento de anti-tamper/anti-debug. É diferente do "timeout" previsto; o bloqueio persiste mesmo após pm clear.
- Parei após a 1ª tentativa genuína + 1 janela vazia (orçamento de tempo ~50 min esgotado; não insisti).

## Comparação offline × runtime
- Não realizada: nenhum JSON runtime gerado (`il2cpp_dump_114_runtime/` vazio/inexistente). Taxa de match: **N/A**. A prova independente das 85 imagens/classes continua pendente.
- Fallback leve (/proc/<pid>/maps): não executado — o processo morreu antes de qualquer leitura; só seria possível com o jogo vivo (leitura de maps via `su` sem attach, rodar numa próxima janela imediatamente após o operador abrir).

## Sugestões
1. Próxima janela: NÃO anexar; só ler `/proc/<pid>/maps` e `/proc/<pid>/mem` via `su` (dd) ou `process_vm_readv` em root — sem ptrace/frida, evitando o gatilho. Verifica base/tamanho libil2cpp vs 75,6 MB e permite varrer a tabela de classes direto pela memória.
2. Alternativas: attach tardio (após a tela principal carregar, >90 s), ou Gadget/zygisk em vez de frida-server (detecção provavelmente por nome `fs17`/porta/threads gum-js).
3. frida-server (fs17, pid 14974) ficou rodando no telefone.
