import os
import json
import zlib
import struct
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from argon2.low_level import hash_secret_raw, Type

# ---------------- CONFIGURAÇÕES ----------------
STORAGE_DIR = "secure_storage"

# ---------------- FUNÇÕES CRIPTOGRÁFICAS ----------------
def _aead_new(key: bytes):
    return ChaCha20Poly1305(key)

def derive_master_key(password: bytes, salt: bytes, argon2_params):
    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=argon2_params["time_cost"],
        memory_cost=argon2_params["memory_cost"],
        parallelism=argon2_params["parallelism"],
        hash_len=argon2_params["hash_len"],
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

def decrypt_file(sf_path: str, password: str, output_dir: str = "."):
    password_bytes = password.encode()

    with open(sf_path, "rb") as f:
        data = f.read()

    offset = 0
    if len(data) < 1:
        raise ValueError("Arquivo corrompido ou vazio.")
    version = struct.unpack_from("<B", data, offset)[0]
    offset += 1

    if len(data) < offset + 2:
        raise ValueError("Arquivo corrompido (salt header).")
    salt_len = struct.unpack_from("<H", data, offset)[0]
    offset += 2

    if len(data) < offset + salt_len:
        raise ValueError("Arquivo corrompido (salt missing).")
    salt = data[offset: offset + salt_len]
    offset += salt_len

    # Leitura do primeiro bloco para pegar os argon2_params nos metadados
    # Precisamos avançar para meta para pegar os parâmetros
    # Primeiro filename
    if len(data) < offset + 4:
        raise ValueError("Arquivo corrompido (filename length).")
    len_filename_enc = struct.unpack_from("<I", data, offset)[0]
    offset += 4
    filename_nonce = data[offset: offset + 12]
    offset += 12
    filename_enc = data[offset: offset + len_filename_enc]
    offset += len_filename_enc

    # Meta
    if len(data) < offset + 4:
        raise ValueError("Arquivo corrompido (meta length).")
    len_meta_enc = struct.unpack_from("<I", data, offset)[0]
    offset += 4
    meta_nonce = data[offset: offset + 12]
    offset += 12
    meta_enc = data[offset: offset + len_meta_enc]
    offset += len_meta_enc

    # Payload
    if len(data) < offset + 8:
        raise ValueError("Arquivo corrompido (payload length).")
    len_payload_enc = struct.unpack_from("<Q", data, offset)[0]
    offset += 8
    payload_nonce = data[offset: offset + 12]
    offset += 12
    payload_enc = data[offset: offset + len_payload_enc]
    offset += len_payload_enc

    # Derivar master key usando parâmetros padrão ou do header
    # Tentaremos extrair argon2_params dos metadados
    try:
        # Primeiro, derivar uma chave temporária para descriptografar meta
        master_key_temp = derive_master_key(password_bytes, salt, {
            "time_cost": 4,
            "memory_cost": 512*1024,
            "parallelism": 4,
            "hash_len": 32
        })
        k_temp = master_key_temp  # usar direto para meta
        meta_comp = _aead_new(k_temp).decrypt(meta_nonce, meta_enc, None)
        metadata = json.loads(zlib.decompress(meta_comp).decode())
        argon2_params = metadata.get("argon2_params", {
            "time_cost": 4,
            "memory_cost": 512*1024,
            "parallelism": 4,
            "hash_len": 32
        })
    except Exception:
        raise ValueError("Não foi possível ler os metadados (senha incorreta ou arquivo corrompido).")

    # Derivar master key final com os parâmetros corretos
    master_key = derive_master_key(password_bytes, salt, argon2_params)
    k_filename, k_meta, k_payload = derive_subkeys(master_key)

    # Descriptografar filename
    try:
        filename_comp = _aead_new(k_filename).decrypt(filename_nonce, filename_enc, None)
        filename = zlib.decompress(filename_comp).decode(errors="ignore")
    except Exception:
        raise ValueError("Falha ao descriptografar o nome do arquivo (senha incorreta?).")

    # Descriptografar meta e payload
    try:
        meta_comp = _aead_new(k_meta).decrypt(meta_nonce, meta_enc, None)
        metadata = json.loads(zlib.decompress(meta_comp).decode())
        payload_comp_padded = _aead_new(k_payload).decrypt(payload_nonce, payload_enc, None)
    except Exception:
        raise ValueError("Falha ao descriptografar metadados ou payload.")

    # Remover padding
    pad_len = metadata.get("pad_len", 0)
    if pad_len:
        payload_comp = payload_comp_padded[:-pad_len]
    else:
        payload_comp = payload_comp_padded

    # Descomprimir conteúdo
    try:
        plaintext_bytes = zlib.decompress(payload_comp)
    except Exception:
        raise ValueError("Falha ao descomprimir o payload.")

    # Salvar arquivo recuperado
    out_path = os.path.join(output_dir, filename)
    base, ext = os.path.splitext(out_path)
    counter = 1
    while os.path.exists(out_path):
        out_path = f"{base}_restored_{counter}{ext}"
        counter += 1

    with open(out_path, "wb") as f:
        f.write(plaintext_bytes)

    return out_path

# ---------------- FUNÇÃO DE GUI SIMPLES ----------------
def decrypt_gui():
    from tkinter import Tk, Label, Entry, Button
    root = Tk()
    root.title("Descriptografar Arquivo Seguro")
    root.geometry("500x180")
    root.configure(bg="#1e1e1e")

    Label(root, text="Senha:", fg="white", bg="#1e1e1e").pack(pady=10)
    pass_entry = Entry(root, show="*", width=40)
    pass_entry.pack(pady=5)

    def select_file_decrypt():
        file_path = filedialog.askopenfilename(filetypes=[("Secure files", "*.sf8aj")])
        if not file_path:
            return
        password = pass_entry.get()
        try:
            out_path = decrypt_file(file_path, password, output_dir=".")
            messagebox.showinfo("Sucesso", f"Arquivo descriptografado e salvo em:\n{out_path}")
        except Exception as e:
            messagebox.showerror("Erro", f"Não foi possível descriptografar o arquivo:\n{str(e)}")

    Button(root, text="Selecionar Arquivo .sf8aj para Descriptografar", command=select_file_decrypt, bg="#4caf50", fg="white", width=40).pack(pady=20)
    root.mainloop()

if __name__ == "__main__":
    decrypt_gui()
