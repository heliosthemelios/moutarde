import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
import getpass
from art import *

moutarde = text2art("MOUTARDE")
print(moutarde)

CHUNK_SIZE = 64 * 1024  # 64 Ko

def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,  # Augmenté à 600 000 (norme de sécurité actuelle)
        backend=default_backend()
    )
    return kdf.derive(password)


def encrypt_file(input_path, output_path, password):
    try:
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = derive_key(password.encode(), salt)
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=default_backend()
        ).encryptor()

        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            f_out.write(salt)
            f_out.write(nonce)
            while chunk := f_in.read(CHUNK_SIZE):
                f_out.write(encryptor.update(chunk))
            f_out.write(encryptor.finalize())
            f_out.write(encryptor.tag)
        return True  # Le chiffrement a réussi
    except Exception as e:
        print(f"Erreur lors du chiffrement de {input_path}: {e}")
        if os.path.exists(output_path):
            os.remove(output_path)
        return False  # Le chiffrement a échoué


def encrypt_folder(folder_path, password, keep_original=False):
    for root, _, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            if file_path.endswith(".enc"):
                continue
            encrypted_path = file_path + ".enc"
            print(f"Chiffrement de : {file_path}")
            
            # On ne supprime l'original QUE si le chiffrement a fonctionné
            succes = encrypt_file(file_path, encrypted_path, password)
            if succes and not keep_original:
                os.remove(file_path)


def decrypt_file(input_path, output_path, password):
    erreur_survenue = False
    try:
        with open(input_path, 'rb') as f_in:
            salt = f_in.read(16)
            nonce = f_in.read(12)
            file_size = os.path.getsize(input_path)

            f_in.seek(file_size - 16)
            tag = f_in.read(16)

            key = derive_key(password.encode(), salt)

            decryptor = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            ).decryptor()

            f_in.seek(28)
            to_read = file_size - 28 - 16
            
            with open(output_path, 'wb') as f_out:
                total = 0
                while total < to_read:
                    chunk = f_in.read(min(CHUNK_SIZE, to_read - total))
                    f_out.write(decryptor.update(chunk))
                    total += len(chunk)
                
                try:
                    f_out.write(decryptor.finalize())
                except InvalidTag:
                    print(f"Erreur : Mot de passe incorrect ou fichier corrompu pour {input_path}")
                    erreur_survenue = True
    except Exception as e:
        print(f"Erreur lors de la lecture du fichier chiffré : {e}")
        erreur_survenue = True

    # Nettoyage et retour du statut
    if erreur_survenue:
        if os.path.exists(output_path):
            os.remove(output_path)
        return False  # ÉCHEC : On prévient la fonction parente
    return True  # SUCCÈS


def decrypt_folder(folder_path, password, keep_encrypted=False):
    for root, _, files in os.walk(folder_path):
        for file_name in files:
            if not file_name.endswith(".enc"):
                continue
            file_path = os.path.join(root, file_name)
            decrypted_path = os.path.join(root, file_name[:-4])
            print(f"Déchiffrement de : {file_path}")
            
            # On récupère le résultat du déchiffrement
            succes = decrypt_file(file_path, decrypted_path, password)
            
            # CRITIQUE : On ne supprime le fichier .enc QUE si le déchiffrement a réussi !
            if succes and not keep_encrypted:
                os.remove(file_path)

def choisir_dossier():
    # Ouvre une vraie fenêtre Windows pour choisir un dossier
    dossier = filedialog.askdirectory()
    if dossier:
        champ_dossier.delete(0, tk.END)
        champ_dossier.insert(0, dossier)

def lancer_chiffrement():
    dossier = champ_dossier.get()
    mdp = champ_mdp.get()
    
    if not dossier or not mdp:
        messagebox.showerror("Erreur", "Veuillez choisir un dossier et un mot de passe.")
        return
        
    encrypt_folder(dossier, mdp)
    messagebox.showinfo("Succès", "Le dossier a été chiffré avec succès !")

def lancer_dechiffrement():
    dossier = champ_dossier.get()
    mdp = champ_mdp.get()
    
    if not dossier or not mdp:
        messagebox.showerror("Erreur", "Veuillez choisir un dossier et un mot de passe.")
        return
        
    decrypt_folder(dossier, mdp)
    messagebox.showinfo("Succès", "Le dossier a été déchiffré avec succès !")

# ==========================================
# CRÉATION DE L'INTERFACE GRAPHIQUE TKINTER
# ==========================================

# 1. Création de la fenêtre principale
fenetre = tk.Tk()
fenetre.title("Moutarde - Chiffrement PDF")
fenetre.geometry("450x250")

# 2. Section pour choisir le dossier
tk.Label(fenetre, text="Dossier cible :").pack(pady=(10, 0))
champ_dossier = tk.Entry(fenetre, width=50)
champ_dossier.pack(pady=5)
bouton_parcourir = tk.Button(fenetre, text="Parcourir...", command=choisir_dossier)
bouton_parcourir.pack()

# 3. Section pour le mot de passe
tk.Label(fenetre, text="Mot de passe :").pack(pady=(10, 0))
champ_mdp = tk.Entry(fenetre, width=30, show="*") # show="*" masque les caractères
champ_mdp.pack(pady=5)

# 4. Boutons d'action
frame_boutons = tk.Frame(fenetre)
frame_boutons.pack(pady=20)

bouton_crypter = tk.Button(frame_boutons, text="🔒 Crypter le dossier", bg="lightcoral", command=lancer_chiffrement)
bouton_crypter.pack(side=tk.LEFT, padx=10)

bouton_decrypter = tk.Button(frame_boutons, text="🔓 Décrypter le dossier", bg="lightgreen", command=lancer_dechiffrement)
bouton_decrypter.pack(side=tk.LEFT, padx=10)

# Lancement de la boucle de l'interface
if __name__ == "__main__":
    fenetre.mainloop()