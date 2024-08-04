from os import urandom
from cast256 import *


def rdm_iv_generator():
    """
    Cette fonction doit pouvoir générer un nombre aléatoire de 128bits
    :return: un entier représenté sur 128 bits généré de manière aléatoire.
    """
    return int.from_bytes(urandom(16), byteorder='big')


def encrypt_ecb(blocks, key):
    """
    Cette fonction applique le chiffrement CAST256 à une liste de blocs de 128 bits suivant le mode d'opération ECB.
    :param blocks: Liste de blocs (128bits) à chiffrer.
    :param key: clé de chiffrement 256 bits
    :return: la liste de blocs chiffrés.
    """
    encrypted_blocks = []
    for block in blocks:
        encrypted_block = encrypt_block(block, key)
        encrypted_blocks.append(encrypted_block)
    return encrypted_blocks


def decrypt_ecb(blocks, key):
    """
    Cette fonction dé-chiffre une liste de blocs de 128 bits qui a été préalablement chiffrée
    avec la méthode CAST256 suivant le mode d'opération ECB.
    :param blocks: Liste de blocs à déchiffrer.
    :param key: clé de chiffrement 256 bits
    Identique à celle utilisée pour le chiffrement.
    :return: la liste de blocs déchiffrés.
    """
    decrypted_blocks = []
    for block in blocks:
        decrypted_block = decrypt_block(block, key)
        decrypted_blocks.append(decrypted_block)
    return decrypted_blocks


def encrypt_cbc(blocks, key):
    """
    Cette fonction applique le chiffrement CAST256 à une liste de blocs de 128 bits suivant le mode d'opération CBC.
    :param blocks: Liste de blocs à chiffrer.
    :param key: clé de chiffrement 256 bits
    :return: la liste de blocs chiffrés avec le vecteur initial utilisé en première position.
    """
    iv = rdm_iv_generator()
    encrypted_blocks = [iv]
    temp_iv = iv

    for block in blocks:
        temp_iv = encrypt_block(block ^ temp_iv, key)
        encrypted_blocks.append(temp_iv)

    return encrypted_blocks


def decrypt_cbc(blocks, key):
    """
    Cette fonction dé-chiffre une liste de blocs de 128 bits qui a été préalablement chiffrée
    avec la méthode CAST256 suivant le mode d'opération CBC.
    :param blocks: Liste de blocs à déchiffrer.
    :param key: clé de chiffrement 256 bits
    Identique à celle utilisée pour le chiffrement.
    :return: la liste de blocs déchiffrés.
    """
    temp_iv = blocks.pop(0)
    decrypted_blocks = []
    for block in blocks:
        decrypted_blocks.append(decrypt_block(block, key) ^ temp_iv)
        temp_iv = block

    return decrypted_blocks


def encrypt_pcbc(blocks, key):
    """
    Cette fonction applique le chiffrement CAST256 à une liste de blocs de 128 bits suivant le mode d'opération PCBC.
    :param blocks: Liste de blocs à chiffrer.
    :param key: clé de chiffrement 256 bits
    :return: la liste de blocs chiffrés avec le vecteur initial utilisé en première position.
    """
    iv = rdm_iv_generator()
    encrypted_blocks = [iv]
    prev_block = iv

    for block in blocks:
        temp = block ^ prev_block
        encrypted_block = encrypt_block(temp, key)
        encrypted_blocks.append(encrypted_block)
        prev_block = encrypted_block ^ block

    return encrypted_blocks


def decrypt_pcbc(blocks, key):
    """
    Cette fonction déchiffre une liste de blocs de 128 bits qui a été préalablement chiffrée
    avec la méthode CAST256 suivant le mode d'opération PCBC.
    :param blocks: Liste de blocs à déchiffrer.
    :param key: clé de chiffrement 256 bits
    Identique à celle utilisée pour le chiffrement.
    :return: la liste de blocs déchiffrés.
    """
    iv = blocks.pop(0)
    decrypted_blocks = []
    prev_block = iv

    for block in blocks:
        decrypted_block = decrypt_block(block, key) ^ prev_block
        decrypted_blocks.append(decrypted_block)
        prev_block = block ^ decrypted_block

    return decrypted_blocks


def encrypt_ofb(blocks, key):
    """
    Cette fonction applique le chiffrement CAST256 à une liste de blocs de 128 bits suivant le mode d'opération OFB.
    :param blocks: Liste de blocs à chiffrer.
    :param key: clé de chiffrement 256 bits
    :return: la liste de blocs chiffrés avec le vecteur initial utilisé en première position.
    """
    iv = rdm_iv_generator()
    encrypted_blocks = [iv]
    temp = iv

    for block in blocks:
        temp = encrypt_block(temp, key)
        encrypted_block = block ^ temp
        encrypted_blocks.append(encrypted_block)

    return encrypted_blocks


def decrypt_ofb(blocks, key):
    """
    Cette fonction déchiffre une liste de blocs de 128 bits qui a été préalablement chiffrée
    avec la méthode CAST256 suivant le mode d'opération OFB.
    :param blocks: Liste de blocs à déchiffrer.
    :param key: clé de chiffrement 256 bits
    Identique à celle utilisée pour le chiffrement.
    :return: la liste de blocs déchiffrés.
    """
    iv = blocks.pop(0)
    decrypted_blocks = []
    temp = iv

    for block in blocks:
        temp = encrypt_block(temp, key)
        decrypted_block = block ^ temp
        decrypted_blocks.append(decrypted_block)

    return decrypted_blocks


def decrypt(blocks, key, operation_mode="ECB"):
    """
    Cette fonction dé-chiffre une liste de blocs de 128 bits qui a été préalablement chiffrée
    avec la méthode CAST256 suivant le mode d'opération CBC ou ECB.
    :param blocks: Liste de blocs à déchiffrer.
    :param key: la clé de chiffrement 256 bit
    :param operation_mode: string spécifiant le mode d'opération ("ECB" ou "CBC")
    :return: la liste de blocs déchiffrés.
    """
    decrypted_blocks = []
    if operation_mode.upper() == 'ECB':
        decrypted_blocks = decrypt_ecb(blocks, key)
    elif operation_mode.upper() == 'CBC':
        decrypted_blocks = decrypt_cbc(blocks, key)
    elif operation_mode.upper() == 'PCBC':
        decrypted_blocks = decrypt_pcbc(blocks, key)
    elif operation_mode.upper() == 'OFB':
        decrypted_blocks = decrypt_ofb(blocks, key)
    else:
        print('Merci de spécifier un mode valide (ECB, CBC, OFB ou PCBC)')
    return decrypted_blocks


def encrypt(blocks, key, operation_mode="ECB"):
    """
    Cette fonction applique le chiffrement CAST256 à une liste de blocs de 128 bits.
    :param blocks: Liste de blocs à chiffrer.
    :param key: la clé de chiffrement 256 bit
    :param operation_mode: string spécifiant le mode d'opération ("ECB" ou "CBC")
    :return: la liste de blocs chiffrés avec le vecteur initial utilisé en première position.
    """
    encrypted_blocks = []
    if operation_mode.upper() == 'ECB':
        encrypted_blocks = encrypt_ecb(blocks, key)
    elif operation_mode.upper() == 'CBC':
        encrypted_blocks = encrypt_cbc(blocks, key)
    elif operation_mode.upper() == 'PCBC':
        encrypted_blocks = encrypt_pcbc(blocks, key)
    elif operation_mode.upper() == 'OFB':
        encrypted_blocks = encrypt_ofb(blocks, key)
    else:
        print('Merci de spécifier un mode valide (ECB, CBC, OFB ou PCBC)')
    return encrypted_blocks
