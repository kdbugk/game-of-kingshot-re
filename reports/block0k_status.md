# BLOCK0-K — Status (sessão 2026-11-19, coberta pelo pai)

**Budget desta sessão foi consumido pelas lanes 1–3** (NES-UNPACK destravou as outras duas:
TERMO-MAP e DETECT-LOGIC dependiam do libnesec desempacotado). Esta lane ficou só no recon —
sem execução de leads. Stop-condition honesta: nada novo foi derivado hoje.

## Recon carregado (não repetir)

De reports/block0_key.md + laneC/block0_statistical.md (sessões anteriores):
- K do bloco 0 é GLOBAL (mesma p/ todos os bundles) e determinística (par de bundles com
  cipher idêntico ⇒ sem nonce).
- Colapso de concordância após byte ~81 ⇒ keystream efetivamente por-bundle dali em diante;
  constraint firme: key[0..48]=0, key[49..80]=0xA6 (janela LZ4).
- Candidatos a gerador: CRC32C poly 0x1EDC6F41 init 0x8f6e37a0 (o MESMO do unpacker HTProtect!),
  LCG, xorshift — semeados por csz/usz/hash-do-nome-CAB.
- Leads não executados hoje: (a) part B do libunity (unity_unpack/crypt_out_*.bin + laneN/rel.pkl
  31.148 relocs) para achar geradores irmãos do HTPX @0x1447040; (b) crib de header UnityFS
  em bundle single-TextAsset.

## Ganho indireto de hoje

O emulador do nesec (emu_unpack_nesec.py) + a prova de que o packer usa **XOR de byte único +
mprotect** na variante nesec sugerem re-checar se o crypt de BUNDLE do libunity também tem um
caminho simples por trás do RC4-mod (a assinatura 37/64 que casava era justamente a parte comum).

## Próximos passos (ordem)

1. Lead (a): decompile ao redor de 0x1447040 no projeto ghidra_unity (já importado) procurando
   funções-irmãs (tabelas CRC/poly) que produzam 4096 B.
2. Lead (b): crib UnityFS em bundle pequeno (work/laneC/collect.py já coleta) → K parcial →
   se LFSR/CRC, extrapolar.
3. Validação: ≥95% bundles → LZ4 → SerializedFile válido.
