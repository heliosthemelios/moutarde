import os
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


def main():
    choix = input("pour crypter (0) : pour decrypter (1) : ")

    if choix == "0":
        # Saisie sécurisée sans afficher le mot de passe à l'écran
        mdp = getpass.getpass("Entrez un mot de passe (gardez-le en sécurité) : ")
        mdp_conf = getpass.getpass("Confirmez le mot de passe : ")
        
        if mdp != mdp_conf:
            print("Les mots de passe ne correspondent pas. Annulation.")
            return
            
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
        motdepasse = getpass.getpass("Entrez le mot de passe de déchiffrement : ")
        decrypt_folder(dossier, motdepasse)
        print("Déchiffrement terminé.")
    else:
        print("Choix invalide.")


if __name__ == "__main__":
    main()

