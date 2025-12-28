"""
Certificate Authority (CA) Server:
- Sistem içindeki tek merkezi sunucudur
- ClientA ve ClientB yalnizca CA ile haberleşir
- Sertifika taleplerini (CERT_REQUEST) karşilar (sembolik)
- Şifreli mesajlari alir ve ClientB’ye iletir
- Gerçek sistemlerdeki CA mantigini sadeleştirilmiş şekilde temsil eder
"""

import socket
import threading
import os
import time

HOST = "0.0.0.0"
PORT = 9000

# CA tek bir master key üretir ve saklar (32 byte)
MASTER_KEY = os.urandom(32)

# CA son gelen şifreli mesajı saklar (örnek için)
LAST_ENCRYPTED_MSG = None
LOCK = threading.Lock()

def handle_client(conn, addr):
    global LAST_ENCRYPTED_MSG
    try:
        data = conn.recv(65535)
        if not data:
            return

        # 1) Sertifika isteği (sembolik)
        if data == b"CERT_REQUEST":
            print(f"[CA] CERT_REQUEST <- {addr}")
            conn.sendall(b"CERT_OK")
            return

        # 2) Master key isteği
        if data == b"GET_MASTER":
            mk_hex = MASTER_KEY.hex().encode()
            conn.sendall(b"MASTER:" + mk_hex)
            print(f"[CA] MASTER gönderildi -> {addr}")
            return

        # 3) ClientA şifreli mesaj gönderir
        if data.startswith(b"MSG:"):
            encrypted = data[4:]
            with LOCK:
                LAST_ENCRYPTED_MSG = encrypted
            print(f"[CA] MSG alındı ({len(encrypted)} byte) <- {addr}")
            conn.sendall(b"MSG_OK")
            return

        # 4) ClientB mesaj çekmek ister (poll)
        if data == b"PULL":
            with LOCK:
                if LAST_ENCRYPTED_MSG is None:
                    conn.sendall(b"NO_MSG")
                else:
                    conn.sendall(b"MSG:" + LAST_ENCRYPTED_MSG)
            return

        conn.sendall(b"UNKNOWN")

    except Exception as e:
        print("[CA] Hata:", e)
    finally:
        conn.close()

def main():
    print(f"[CA] Sunucu çalışıyor -> {HOST}:{PORT}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(50)

    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()
