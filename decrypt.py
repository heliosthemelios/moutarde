import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from art import *

text=text2art("MOUTARDE")
print(text)

CHUNK_SIZE = 64 * 1024  # 64 Ko

def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password)

def decrypt_file(input_path, output_path, password):
    with open(input_path, 'rb') as f_in:
        salt = f_in.read(16)
        nonce = f_in.read(12)

        file_size = os.path.getsize(input_path)
        encrypted_size = file_size - 16 - 12 - 16  # sans salt, nonce, tag
        key = derive_key(password.encode(), salt)

        f_in.seek(28)
        tag_pos = file_size - 16
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, f_in.read()[-16:]),
            backend=default_backend()
        ).decryptor()

        f_in.seek(28)
        to_read = encrypted_size
        with open(output_path, 'wb') as f_out:
            total = 0
            while total < to_read:
                chunk = f_in.read(min(CHUNK_SIZE, to_read - total))
                f_out.write(decryptor.update(chunk))
                total += len(chunk)
            f_out.write(decryptor.finalize())

def decrypt_folder(folder_path, password, keep_encrypted=False):
    for root, dirs, files in os.walk(folder_path):
        for file_name in files:
            if not file_name.endswith(".enc"):
                continue  # ignorer les fichiers non chiffrés
            file_path = os.path.join(root, file_name)
            decrypted_path = os.path.join(root, file_name[:-4])  # enlève ".enc"
            print(f"Déchiffrement de : {file_path}")
            decrypt_file(file_path, decrypted_path, password)
            if not keep_encrypted:
                os.remove(file_path)

if __name__ == "__main__":
    dossier = "text"  # <-- Le dossier contenant les .enc
    motdepasse = input("entrez le mot de passe-->: ")   # <-- Le même mot de passe que pour le chiffrement
    decrypt_folder(dossier, motdepasse)
    print("Déchiffrement terminé.")
