from random import *
from cast256 import *


def rdm_iv_generator():
    """
    Cette fonction doit pouvoir générer un nombre aléatoire de 128bits
    :return: un entier représenté sur 128 bits généré de manière aléatoire.
    """
    n = 0
    for _ in range(4):
        n = (n << 32) | getrandbits(32)

    return n


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
    encrypted_blocks = []
    iv = rdm_iv_generator()
    prev_enc_block = iv

    for block in blocks:
        pre_encrypted_block = block ^ prev_enc_block

        encrypted_block = encrypt_block(pre_encrypted_block, key)

        prev_enc_block = encrypted_block

        encrypted_blocks.append(encrypted_block)

    encrypted_blocks.insert(0, iv)

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
    decrypted_blocks = []
    iv = blocks[0]
    prev_cipher_block = iv

    for block in blocks[1:]:
        pre_decrypt_block = decrypt_block(block, key)

        decrypted_block = pre_decrypt_block ^ prev_cipher_block

        prev_cipher_block = block

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
    else:
        print('Merci de spécifier un mode valide (ECB ou CBC)')
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
    else:
        print('Merci de spécifier un mode valide (ECB ou CBC)')
    return encrypted_blocks
