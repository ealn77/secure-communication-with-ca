"""
ClientB:
- CA sunucusuna bağlanir
- CA üzerinden gelen şifreli mesajlari dinler (PULL)
- Session key kullanarak AES ile şifreyi çözer
- Şifreli veriyi (hex) ve çözülen açik mesaji gösterir
"""

import socket
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

CA_IP = "192.168.1.59"
CA_PORT = 9000

master_key = None
session_key = None

def request_from_ca(payload: bytes) -> bytes | None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((CA_IP, CA_PORT))
        s.sendall(payload)
        data = s.recv(65535)
        s.close()
        return data
    except Exception as e:
        print("[ClientB] CA bağlantı hatası:", e)
        return None

def derive_session_key(master: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"session-key"
    )
    return hkdf.derive(master)

def decrypt_message(blob: bytes, key: bytes) -> str:
    # blob = IV(16) + ciphertext
    iv = blob[:16]
    ciphertext = blob[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plain = decryptor.update(ciphertext) + decryptor.finalize()
    return plain.decode("utf-8", errors="replace")

def main():
    global master_key, session_key

    # 1) Master key al
    resp = request_from_ca(b"GET_MASTER")
    if not resp or not resp.startswith(b"MASTER:"):
        print("[ClientB] Master Key alınamadı. CA çalışıyor mu?")
        return

    mk_hex = resp.split(b":", 1)[1].decode()
    master_key = bytes.fromhex(mk_hex)
    session_key = derive_session_key(master_key)

    print("[ClientB] Master Key alındı (hex):", mk_hex)
    print("[ClientB] Session Key türetildi (hex):", session_key.hex())
    print("[ClientB] CA'dan mesaj bekleniyor... (PULL ile)")

    # 2) Sürekli CA'dan mesaj çek (poll)
    last_seen = None
    while True:
        resp = request_from_ca(b"PULL")
        if resp and resp.startswith(b"MSG:"):
            encrypted = resp[4:]
            if encrypted != last_seen:
                last_seen = encrypted
                print("\n[ClientB] Şifreli veri (hex):", encrypted.hex())
                try:
                    plain = decrypt_message(encrypted, session_key)
                    print("[ClientB] Çözülen mesaj:", plain)
                except Exception as e:
                    print("[ClientB] Decrypt hatası:", e)

        time.sleep(1)

if __name__ == "__main__":
    main()