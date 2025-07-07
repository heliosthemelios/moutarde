import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_file(filepath: str, password: str):
    salt = os.urandom(16)
    key = generate_key(password, salt)
    iv = os.urandom(12)

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(filepath, 'rb') as f_in:
        plaintext = f_in.read()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag

    encrypted_filepath = filepath + ".enc"
    with open(encrypted_filepath, 'wb') as f_out:
        f_out.write(salt)
        f_out.write(iv)
        f_out.write(tag)
        f_out.write(ciphertext)

    return encrypted_filepath

def decrypt_file(filepath: str, password: str):
    try:
        with open(filepath, 'rb') as f_in:
            salt = f_in.read(16)
            iv = f_in.read(12)
            tag = f_in.read(16)
            ciphertext = f_in.read()

        key = generate_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()

        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        decrypted_filepath = filepath.replace(".enc", ".decrypted")

        with open(decrypted_filepath, 'wb') as f_out:
            f_out.write(plaintext)

        return decrypted_filepath

    except Exception as e:
        raise ValueError("Erreur lors du déchiffrement : mot de passe incorrect ou fichier corrompu.")

# Interface graphique
class CryptoApp:
    def __init__(self, master):
        self.master = master
        master.title("Chiffrement de fichiers")
        master.geometry("400x250")

        self.label = tk.Label(master, text="Choisissez un fichier à chiffrer/déchiffrer :")
        self.label.pack(pady=10)

        self.file_path = tk.StringVar()
        self.file_entry = tk.Entry(master, textvariable=self.file_path, width=50)
        self.file_entry.pack()

        self.browse_button = tk.Button(master, text="Parcourir", command=self.browse_file)
        self.browse_button.pack(pady=5)

        self.password_label = tk.Label(master, text="Mot de passe :")
        self.password_label.pack()

        self.password_entry = tk.Entry(master, show="*")
        self.password_entry.pack(pady=5)

        self.encrypt_button = tk.Button(master, text="Chiffrer", command=self.encrypt)
        self.encrypt_button.pack(pady=5)

        self.decrypt_button = tk.Button(master, text="Déchiffrer", command=self.decrypt)
        self.decrypt_button.pack(pady=5)

    def browse_file(self):
        filepath = filedialog.askopenfilename()
        if filepath:
            self.file_path.set(filepath)

    def encrypt(self):
        path = self.file_path.get()
        password = self.password_entry.get()
        if not path or not password:
            messagebox.showwarning("Erreur", "Veuillez sélectionner un fichier et entrer un mot de passe.")
            return
        try:
            encrypted_path = encrypt_file(path, password)
            messagebox.showinfo("Succès", f"Fichier chiffré : {encrypted_path}")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors du chiffrement : {e}")

    def decrypt(self):
        path = self.file_path.get()
        password = self.password_entry.get()
        if not path or not password:
            messagebox.showwarning("Erreur", "Veuillez sélectionner un fichier et entrer un mot de passe.")
            return
        try:
            decrypted_path = decrypt_file(path, password)
            messagebox.showinfo("Succès", f"Fichier déchiffré : {decrypted_path}")
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
