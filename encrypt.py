import os
import json
import zlib
import struct
import uuid
from tkinter import Tk, Label, Entry, Button, filedialog, messagebox
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from argon2.low_level import hash_secret_raw, Type
import re

# ---------------- CONFIGURAÇÕES ----------------
ARGON2_PARAMS = {
    "time_cost": 4,
    "memory_cost": 512 * 1024,  # 512 MiB
    "parallelism": 4,
    "hash_len": 32,
}
MIN_PAD_BYTES = 1024 * 1024
STORAGE_DIR = "secure_storage"
FORMAT_VERSION = 1

# ---------------- FUNÇÕES CRIPTOGRÁFICAS ----------------
def _aead_new(key: bytes):
    return ChaCha20Poly1305(key)

def derive_master_key(password: bytes, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=ARGON2_PARAMS["time_cost"],
        memory_cost=ARGON2_PARAMS["memory_cost"],
        parallelism=ARGON2_PARAMS["parallelism"],
        hash_len=ARGON2_PARAMS["hash_len"],
        type=Type.ID
    )

def derive_subkeys(master_key: bytes):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32 * 3,
        salt=None,
        info=b"nuvora-file-keys",
    )
    okm = hkdf.derive(master_key)
    return okm[:32], okm[32:64], okm[64:96]

def encrypt_file(file_path: str, password: str):
    password_bytes = password.encode()
    os.makedirs(STORAGE_DIR, exist_ok=True)

    with open(file_path, "rb") as f:
        plaintext_bytes = f.read()

    # Salt aleatório por arquivo
    salt = os.urandom(16)
    master_key = derive_master_key(password_bytes, salt)
    k_filename, k_meta, k_payload = derive_subkeys(master_key)

    # Criptografar nome do arquivo
    filename = os.path.basename(file_path).encode()
    filename_comp = zlib.compress(filename, level=6)
    filename_nonce = os.urandom(12)
    filename_enc = _aead_new(k_filename).encrypt(filename_nonce, filename_comp, None)

    # Comprimir e adicionar padding adaptativo
    payload_comp = zlib.compress(plaintext_bytes, level=6)
    pad_needed = (MIN_PAD_BYTES - (len(payload_comp) % MIN_PAD_BYTES)) % MIN_PAD_BYTES
    if pad_needed:
        payload_comp += os.urandom(pad_needed)

    # Metadados
    metadata = {
        "orig_len": len(plaintext_bytes),
        "pad_len": pad_needed,
        "alg": "ChaCha20-Poly1305",
        "filename_len": len(filename),
        "argon2_params": ARGON2_PARAMS,
        "format_version": FORMAT_VERSION
    }
    meta_plain = json.dumps(metadata).encode()
    meta_comp = zlib.compress(meta_plain, level=6)
    meta_nonce = os.urandom(12)
    meta_enc = _aead_new(k_meta).encrypt(meta_nonce, meta_comp, None)

    # Criptografar payload
    payload_nonce = os.urandom(12)
    payload_enc = _aead_new(k_payload).encrypt(payload_nonce, payload_comp, None)

    # Montar arquivo final com salt e cabeçalho
    buf = bytearray()
    buf += struct.pack("<B", FORMAT_VERSION)  # versão
    buf += struct.pack("<H", len(salt)) + salt

    buf += struct.pack("<I", len(filename_enc)) + filename_nonce + filename_enc
    buf += struct.pack("<I", len(meta_enc)) + meta_nonce + meta_enc
    buf += struct.pack("<Q", len(payload_enc)) + payload_nonce + payload_enc

    # Nome final aleatório
    out_name = uuid.uuid4().hex + ".sf8aj"
    out_path = os.path.join(STORAGE_DIR, out_name)
    with open(out_path, "wb") as f:
        f.write(buf)

    return out_path

# ---------------- INTERFACE TKINTER ----------------
class EncryptApp:
    def __init__(self):
        self.root = Tk()
        self.root.title("Criptografar Arquivo Seguro")
        self.root.geometry("560x200")
        self.root.configure(bg="#1e1e1e")

        Label(self.root, text="Senha (12-64 chars recomendados, maiúscula, minúscula, número e símbolo):", fg="white", bg="#1e1e1e").pack(pady=10)
        self.pass_entry = Entry(self.root, show="*", width=50)
        self.pass_entry.pack(pady=5)

        Button(self.root, text="Selecionar Arquivo para Criptografar", command=self.select_file_encrypt, bg="#2196f3", fg="white", width=40).pack(pady=20)
        Label(self.root, text="Arquivos criptografados são salvos em ./secure_storage", fg="white", bg="#1e1e1e").pack(pady=5)

        self.root.mainloop()

    def validate_password(self, password):
        if not (12 <= len(password) <= 64): return False
        if not re.search(r"[A-Z]", password): return False
        if not re.search(r"[a-z]", password): return False
        if not re.search(r"[0-9]", password): return False
        if not re.search(r"[^A-Za-z0-9]", password): return False
        return True

    def select_file_encrypt(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        password = self.pass_entry.get()
        if not self.validate_password(password):
            messagebox.showerror("Erro", "Senha inválida! Deve ter 12-64 caracteres com maiúscula, minúscula, número e símbolo.")
            return
        try:
            out_path = encrypt_file(file_path, password)
            messagebox.showinfo("Sucesso", f"Arquivo criptografado e salvo em:\n{out_path}")
        except Exception as e:
            messagebox.showerror("Erro", f"Não foi possível criptografar o arquivo:\n{str(e)}")

if __name__ == "__main__":
    EncryptApp()
