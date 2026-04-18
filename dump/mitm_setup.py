"""
mitm_setup.py

Prepara o ambiente MITM para interceptar tráfego do com.run.tower.defense.

Passos:
  1. Gera CA do mitmproxy (roda mitmdump brevemente para criar ~/.mitmproxy/)
  2. Calcula o hash OpenSSL do cert (formato Android system CA)
  3. Push do cert para /sdcard/
  4. Instala como CA de sistema em /system/etc/security/cacerts/<hash>.0
  5. Imprime instruções para configurar proxy WiFi no Android

Uso:
  python mitm_setup.py

Depois execute:
  mitmdump_capture.py    (captura o tráfego)
"""

import subprocess
import sys
import os
import time
from pathlib import Path

PROXY_HOST = "192.168.0.84"
PROXY_PORT = 8080
ADB        = "adb"
MITMDUMP   = r"C:\Users\prs\AppData\Local\Python\pythoncore-3.14-64\Scripts\mitmdump.exe"
MITMDIR    = Path.home() / ".mitmproxy"
CERT_PEM   = MITMDIR / "mitmproxy-ca-cert.pem"
CERT_DER   = MITMDIR / "mitmproxy-ca-cert-der.cer"  # gerado por mitmdump automaticamente

def run(cmd, check=True, capture=False):
    print(f"  $ {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    result = subprocess.run(
        cmd, shell=isinstance(cmd, str),
        capture_output=capture, text=True
    )
    if check and result.returncode != 0:
        print(f"  [!] falhou (rc={result.returncode})")
        if capture:
            print(result.stderr)
    return result

def step1_gerar_ca():
    print("\n[1] Gerando CA do mitmproxy...")
    if CERT_PEM.exists():
        print(f"  CA já existe: {CERT_PEM}")
        return True

    print("  Rodando mitmdump por 2s para gerar CA...")
    proc = subprocess.Popen(
        [MITMDUMP, "--listen-port", str(PROXY_PORT), "--quiet"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(3)
    proc.terminate()
    proc.wait()

    if CERT_PEM.exists():
        print(f"  CA gerado: {CERT_PEM}")
        return True
    else:
        print(f"  [!] CA não encontrado em {CERT_PEM}")
        return False

def step2_calcular_hash():
    print("\n[2] Calculando hash do certificado (formato Android)...")
    # Android exige o nome do arquivo = <subject_hash_old>.0
    # openssl x509 -inform PEM -subject_hash_old -in cert.pem
    result = run(
        f'openssl x509 -inform PEM -subject_hash_old -in "{CERT_PEM}" -noout',
        check=False, capture=True
    )
    if result.returncode != 0 or not result.stdout.strip():
        print("  [!] openssl falhou. Tentando via Python (cryptography)...")
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            import hashlib, struct

            cert_data = CERT_PEM.read_bytes()
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            # subject_hash_old = MD5 do subject DER com módulo 2^32
            subject_der = cert.subject.public_bytes()
            h = hashlib.md5(subject_der).digest()
            hash_val = struct.unpack("<L", h[:4])[0]
            cert_hash = f"{hash_val:08x}"
            print(f"  hash (via Python): {cert_hash}")
            return cert_hash
        except ImportError:
            print("  [!] pip install cryptography para usar o fallback Python")
            return None
    else:
        cert_hash = result.stdout.strip().split('\n')[0]
        print(f"  hash: {cert_hash}")
        return cert_hash

def step3_push_cert(cert_hash):
    print("\n[3] Push do certificado para o dispositivo...")
    dest_name = f"{cert_hash}.0"

    # Copia o PEM com o nome correto
    local_cert = MITMDIR / dest_name
    import shutil
    shutil.copy(CERT_PEM, local_cert)
    print(f"  arquivo local: {local_cert}")

    run([ADB, "push", str(local_cert), f"/sdcard/{dest_name}"])
    return dest_name

def step4_instalar_system_ca(dest_name):
    print(f"\n[4] Instalando {dest_name} como CA de sistema (Android 10+/APEX)...")
    # No Android 10+, os CAs sao carregados de /apex/com.android.conscrypt/cacerts/
    # /system/etc/security/cacerts/ nao e mais consultado diretamente.
    # Solucao: montar tmpfs sobre o diretorio APEX e adicionar o cert la.
    apex_ca = "/apex/com.android.conscrypt/cacerts"
    tmp_dir = "/data/local/tmp/cacerts-combined"

    cmds = [
        # Copia todos os CAs existentes para tmp
        f"mkdir -p {tmp_dir}",
        f"cp {apex_ca}/* {tmp_dir}/",
        # Adiciona nosso cert
        f"cp /sdcard/{dest_name} {tmp_dir}/{dest_name}",
        f"chmod 644 {tmp_dir}/{dest_name}",
        # Monta tmpfs sobre o diretorio APEX (sobrevive ate reinicio)
        f"mount -t tmpfs tmpfs {apex_ca}",
        # Copia tudo de volta para o tmpfs
        f"cp {tmp_dir}/* {apex_ca}/",
        f"chown root:root {apex_ca}/*",
        f"chmod 644 {apex_ca}/*",
        f"chcon u:object_r:system_file:s0 {apex_ca}/*",
    ]

    for cmd in cmds:
        run([ADB, "shell", "su", "-c", cmd])

    # Verifica
    result = run(
        [ADB, "shell", "su", "-c", f"ls -la {apex_ca}/{dest_name}"],
        capture=True
    )
    if result.returncode == 0:
        print(f"  OK: {result.stdout.strip()}")
        return True
    else:
        print(f"  [!] falhou: {result.stderr.strip()}")
        # Fallback: tenta /system tambem (Android < 10)
        print("  Tentando fallback /system/etc/security/cacerts...")
        system_ca_dir = "/system/etc/security/cacerts"
        run([ADB, "shell", "su", "-c", f"mount -o rw,remount /system"], check=False)
        run([ADB, "shell", "su", "-c", f"cp /sdcard/{dest_name} {system_ca_dir}/{dest_name}"], check=False)
        run([ADB, "shell", "su", "-c", f"chmod 644 {system_ca_dir}/{dest_name}"], check=False)
        run([ADB, "shell", "su", "-c", f"mount -o ro,remount /system"], check=False)
        result2 = run([ADB, "shell", "su", "-c", f"ls {system_ca_dir}/{dest_name}"], capture=True, check=False)
        if result2.returncode == 0:
            print(f"  OK via /system fallback")
            return True
        return False

def step5_instrucoes():
    print(f"""
[5] Configure o proxy WiFi no Android:
    Configuracoes -> Wi-Fi -> (segure a rede) -> Modificar rede -> Avancado
    Proxy: Manual
    Hostname: {PROXY_HOST}
    Porta:    {PROXY_PORT}

    Ou via adb:
    $ adb shell settings put global http_proxy {PROXY_HOST}:{PROXY_PORT}

[6] Para capturar o trafego:
    python mitmdump_capture.py

[7] Para ver o trafego em tempo real (web UI):
    mitmweb --listen-port {PROXY_PORT}
    Abra http://127.0.0.1:8081 no navegador

[8] Para remover o proxy depois:
    $ adb shell settings delete global http_proxy
""")

def main():
    print("=" * 60)
    print("  MITM Setup — com.run.tower.defense")
    print("=" * 60)

    if not step1_gerar_ca():
        sys.exit(1)

    cert_hash = step2_calcular_hash()
    if not cert_hash:
        print("\n  [!] Não foi possível calcular o hash. Instale openssl ou cryptography.")
        print("  Tente: pip install cryptography")
        sys.exit(1)

    dest_name = step3_push_cert(cert_hash)
    ok = step4_instalar_system_ca(dest_name)

    if ok:
        print("\n  CA instalado com sucesso!")
    else:
        print("\n  [!] Instalação do CA falhou. Verifique:")
        print("      1. Dispositivo conectado via adb")
        print("      2. Magisk + su funcionando")
        print("      3. /system montável como rw")

    step5_instrucoes()

if __name__ == "__main__":
    main()
