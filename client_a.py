"""
ClientA:
- CA’dan sertifika talep eder
- Master key üretir
- HKDF ile session key türetir
- Mesaji AES ile şifreleyip CA’ya gönderir
"""

import socket
import tkinter as tk
from tkinter import ttk, messagebox
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

CA_IP = "192.168.1.59"
CA_PORT = 9000

master_key = None
session_key = None

# ----------------- CA İLETİŞİM -----------------
def request_from_ca(payload: bytes) -> bytes | None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((CA_IP, CA_PORT))
        s.sendall(payload)
        data = s.recv(65535)
        s.close()
        return data
    except Exception as e:
        print("CA bağlantı hatası:", e)
        return None

# ----------------- AES ŞİFRELEME -----------------
def encrypt_message(message: str, key: bytes) -> bytes:
    # AES-CFB: IV + ciphertext döndürüyoruz
    iv = os_urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode("utf-8")) + encryptor.finalize()
    return iv + ciphertext

def os_urandom(n: int) -> bytes:
    import os
    return os.urandom(n)

# ----------------- SERTİFİKA -----------------
def request_certificate():
    resp = request_from_ca(b"CERT_REQUEST")
    if resp == b"CERT_OK":
        cert_text.delete("1.0", tk.END)
        cert_text.insert(tk.END, "✔ CA Sertifikası alındı\n(Sembolik doğrulama tamam)")
    else:
        messagebox.showerror("Hata", "CA'ya bağlanılamadı veya yanıt hatalı!")

# ----------------- MASTER KEY (CA’dan al) -----------------
def get_master_key_from_ca():
    global master_key
    resp = request_from_ca(b"GET_MASTER")
    if not resp or not resp.startswith(b"MASTER:"):
        messagebox.showerror("Hata", "Master Key alınamadı! (CA çalışıyor mu?)")
        return

    mk_hex = resp.split(b":", 1)[1].decode()
    master_key = bytes.fromhex(mk_hex)
    master_key_label.config(text=mk_hex)
    messagebox.showinfo("Başarılı", "Master Key CA'dan alındı")

# ----------------- SESSION KEY (HKDF) -----------------
def create_session_key():
    global session_key
    if not master_key:
        messagebox.showwarning("Uyarı", "Önce CA'dan Master Key al!")
        return

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"session-key"
    )
    session_key = hkdf.derive(master_key)
    session_key_label.config(text=session_key.hex())
    messagebox.showinfo("Başarılı", "Session Key türetildi (HKDF)")

# ----------------- MESAJ GÖNDER (ŞİFRELİ -> CA) -----------------
def send_message():
    if not session_key:
        messagebox.showwarning("Uyarı", "Önce Session Key oluştur!")
        return

    msg = message_entry.get().strip()
    if not msg:
        return

    encrypted = encrypt_message(msg, session_key)
    resp = request_from_ca(b"MSG:" + encrypted)

    if resp == b"MSG_OK":
        messagebox.showinfo("Başarılı", "Şifreli mesaj CA'ya gönderildi")
    else:
        messagebox.showerror("Hata", "Mesaj gönderilemedi (CA çalışıyor mu?)")

# ----------------- GUI -----------------
root = tk.Tk()
root.title("ClientA - Güvenli İstemci")
root.geometry("600x420")

tabs = ttk.Notebook(root)
tabs.pack(expand=True, fill="both")

# TAB 1: Sertifika
tab_cert = ttk.Frame(tabs)
tabs.add(tab_cert, text="Sertifika")

ttk.Button(tab_cert, text="CA'dan Sertifika Al", command=request_certificate).pack(pady=10)
cert_text = tk.Text(tab_cert, height=10)
cert_text.pack(padx=10, pady=10, fill="both")

# TAB 2: Anahtarlar
tab_keys = ttk.Frame(tabs)
tabs.add(tab_keys, text="Anahtarlar")

ttk.Button(tab_keys, text="CA'dan Master Key Al", command=get_master_key_from_ca).pack(pady=8)
master_key_label = ttk.Label(tab_keys, text="—", wraplength=560)
master_key_label.pack(pady=6)

ttk.Button(tab_keys, text="Session Key Oluştur (HKDF)", command=create_session_key).pack(pady=8)
session_key_label = ttk.Label(tab_keys, text="—", wraplength=560)
session_key_label.pack(pady=6)

# TAB 3: Mesaj
tab_msg = ttk.Frame(tabs)
tabs.add(tab_msg, text="Mesaj Gönder")

message_entry = ttk.Entry(tab_msg, width=70)
message_entry.pack(pady=15)
ttk.Button(tab_msg, text="Mesajı Şifrele + CA'ya Gönder", command=send_message).pack()

root.mainloop()
