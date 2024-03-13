from functions_cast256 import *
from math import *


def forward_octave(abcdefgh, tr, tm):
    """
      Cette fonction correspond à la forward_octave du cast-256. Elle décompose le bloc d'entrée 256bits en
      blocs de 32bits. Ces blocs sont transformés par l'utilisation des fonctions f1, f2 et f3 du cast-256 en utilisant
      les clés de rotation et de masque. Les blocs obtenus sont recomposés en un bloc de 256bits.
      !!! ATTENTION A L'ORDRE DES OPERATIONS INDIQUE DANS LA DOCUMENTATION !!!
      :param abcdefgh: le bloc à traité (256bits)
      :param tr: tableau de 8 clés de rotation (8bits)
      :param tm: tableau de 8 clés de masque (32bits)
      :return: le résultat des opérations (256bits)
      """
    a, b, c, d, e, f, g, h = extract_32bit_bloc_from_256(abcdefgh)

    g = g ^ function1(h, tr[0], tm[0])
    f = f ^ function2(g, tr[1], tm[1])
    e = e ^ function3(f, tr[2], tm[2])
    d = d ^ function1(e, tr[3], tm[3])
    c = c ^ function2(d, tr[4], tm[4])
    b = b ^ function3(c, tr[5], tm[5])
    a = a ^ function1(b, tr[6], tm[6])
    h = h ^ function2(a, tr[7], tm[7])

    rs = build_256_bit_bloc_from_32_bit_blocs(a, b, c, d, e, f, g, h)

    return rs


def initialization():
    """
    Cette fonction crée les clés de rotation tr et de masque tm utiles à la génération des clés du cast-256.
    :return: deux tableaux à deux dimensions 8x24 (24 lignes et 8 colonnes) contenant respectivement
    les clés de rotation tr et de masque tm.
    """
    tr, tm = [[0] * 8 for _ in range(24)], [[0] * 8 for _ in range(24)]
    cm = 2**30 * sqrt(2)
    mm = 2**30 * sqrt(3)
    cr = 19
    mr = 17
    for i in range(0, 24):
        for j in range(0, 8):
            tm[i][j] = cm
            cm = sum_mod_232(cm, mm)
            tr[i][j] = cr
            cr = sum_mod_232(cr, mr)

    return tr, tm


def key_generator(key):
    """
    Cette fonction génère les clés de rotation kr et de masque km pour le chiffrement cast-256 à partir de la clé 256bits
    de chiffrement et des clés de rotation tr et de masque tm.
    :param key: la clé de chiffrement (256bits)
    :return: deux tableaux à deux dimensions 12x4 (12 lignes et 4 colonnes) contenant respectivement
    les clés de rotation kr et de masque km.
    """
    kr, km = [], []
    tr, tm = initialization()
    for i in range(0, 24, 2):
        key = forward_octave(key, tr[i], tm[i])
        key = forward_octave(key, tr[i+1], tm[i+1])
        a, b, c, d, e, f, g, h = extract_32bit_bloc_from_256(key)
        a = a & 0b11111
        c = c & 0b11111
        e = e & 0b11111
        g = g & 0b11111
        kr.append([a, c, e, g])
        km.append([h, f, d, b])
    return kr, km
