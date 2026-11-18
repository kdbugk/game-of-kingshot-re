# meta_recon — reconstrução do header de global-metadata (PT-BR)

## Resultado: NÃO FOI POSSÍVEL — o dump `metadata_live_dump.bin` NÃO é o buffer de metadata

Nenhum `global_metadata_rebuilt.dat` foi gerado (nada válido a gerar). Il2CppDumper não foi executado.

## Evidências (todas sobre /home/re/work/apk/metadata_live_dump.bin, 0x1800000 bytes)
1. **Sem string heap do metadata**: a string `.ctor\0`, `.cctor\0`, `<Module>\0`, `mscorlib\0`, `get_Instance\0`,
   `System.Collections.Generic\0`, `Assembly-CSharp.dll` ocorrem **0 vezes**. Todo metadata il2cpp real tem
   `<Module>`, `.ctor`, `mscorlib` etc. no string heap (MB de identificadores contíguos separados por \0).
2. Maior run contíguo de identificadores separados por \0: **2820 bytes** (0xb90655), todos nomes de campos de
   serialização/TypeTree do Unity (`m_Maskable`, `m_PixelsToUnits`, `ShapeModule`...) — repetidos várias vezes
   (0x51f125, 0x52008c, 0x59cf45...), típico de heap de runtime, não de tabela única de strings.
3. Vizinhança das âncoras: `Assembly-CSharp\0` (0xa0e0), `NetSecProtect\0` (0x37b060), `SoundConfig\0` (0xa088)
   estão **cercadas por ponteiros 0x6d........ e structs de objeto** (campos de 8 bytes, vtables/ponteiros
   0x6d10000xxx, 0x6d40xxxxxx) — são strings isoladas dentro de objetos/structs alocados em heap
   (nomes de classe/asm/arquivo), não um string heap sequencial.
4. Classificação por página 4KB: strings só aparecem em páginas isoladas intercaladas com binário (B/S alternados
   de 0x9f3000 até 0xd11000+); não existe bloco grande de texto.
5. Header 0x00–0x110: não tem sanity 0xFAB11BAF (busca por `af 1b b1 fa` = 0 ocorrências no arquivo todo);
   os primeiros 0x110 bytes são ponteiros 0x6d... e contadores (cabeçalho de arena/alocador, ex.: `b81359976d`,
   `e0ff7f116d`, `e0ff3f106d`, `580000106d`), e depois de 0x110 vêm tabelas de ponteiros/zeros (0x1a0–0x2a0 = zeros),
   não tabelas u32 de metadata (ex. nenhum padrão de typeDef/images de 85 entradas).
6. Tabela de tipos "256+ ponteiros" em ~0x6fbd20 é overlay de runtime (consistente com a instrução), mas o
   restante também é heap — não há tabelas de metadata "intactas" por trás.

## Conclusão
A região 0x6d10000000 (24MB rw) é uma **arena de heap do il2cpp/Unity** (Il2CppClass/Image/Assembly/TypeTree structs, nomes
copiados), e não o buffer mapeado do global-metadata.dat. As conclusões anteriores ("metadata decriptado localizado,
header clobberado") parecem ter sido falso positivo (o scan achou nomes de assembly dentro de structs).
Reconstruir header é inviável: não há tabelas para ancorar offsets.

## O que ainda dá para aproveitar deste dump
- Structs Il2CppImage/Il2CppAssembly (name ptr em +0; ver notas anteriores) e Il2CppClass (name +0x10, ns +0x18)
  permitem listar classes/nomes (já planejado em waitgame_dump.py) — dump de nomes, não de metadata completo.

## Próximos passos sugeridos
1. No processo em execução, varrer **todas** as regiões de memória (rw e r--, inclusive mmap anônimo grande e arquivos)
   por `AF 1B B1 FA` seguido de version u32 (24..31) — header intacto pode existir se o buffer decriptado não foi
   zerado; ou por `<Module>\0.ctor\0` / `mscorlib\0`+`System.Collections.Generic\0` em runs >1MB.
2. Alternativa: hookar a função de load do metadata (il2cpp::vm::MetadataLoader::LoadMetadataFile / S_GlobalMetadata
   ponteiro global) — o ponteiro para o header fica em variável global em libil2cpp (`s_GlobalMetadata`); lê-lo via
   relocação/GOT do libil2cpp_decrypted.so e dumpar `s_GlobalMetadataHeader->stringLength...` para tamanho total.
3. Alternativa offline: usar o emulador Unicorn (já quebrou packer) para executar a rotina que decifra metadata do
   arquivo global-metadata.dat criptografado em assets e dumpar a saída.

Scripts: C:/Users/prs/work/meta_recon/{a,b,c,e,f}.py
