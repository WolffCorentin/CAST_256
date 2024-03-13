"""
Ce fichier comprend une série de fonctions utiles qui effectuent des opérations basiques arithmétiques et binaires
"""


def sum_mod_232(a, b):
    """
    Cette fonction effectue une somme dans un espace modulo 2 puissance 32
    :param a: premier terme
    :param b: second terme
    :return: la somme modulo 2 puissance 32
    """
    rs = int(a) + int(b)
    rs = rs % (2 ** 32)
    return int(rs)


def diff_mod_232(a, b):
    """
    Cette fonction effectue une différence dans un espace modulo 2 puissance 32
    :param a: premier terme
    :param b: second terme
    :return: la différence entre me premier et le second terme modulo 2 puissance 32
    """
    rs = int(a) - int(b)
    rs = rs % (2 ** 32)
    return int(rs)


def build_128_bit_bloc_from_32_bit_blocs(a, b, c, d):
    """
    Cette fonction assemble des blocs de 32bits en un seul bloc de 128 bit. Les blocs en paramètres sont ordonnées
    du plus fort au plus faible, c'est-à-dire, dans l'odre d'apparition final de gauche à droite
    :param a: 1er bloc de 32bits
    :param b: 2ème bloc de 32bits
    :param c: 3ème bloc de 32 bits
    :param d: 4ème bloc de 32bits
    :return: un bloc de 128 bits correspondant à l'ordre 'abcd'
    """
    rs = (a << 96) | (b << 64) | (c << 32) | d
    return rs


def extract_32bit_bloc_from_128(abcd):
    """
    Cette fonction décompose un bloc de 128 bits en 4 blocs de 32bits. Les blocs de sortie sont sont ordonnées
    du plus fort au plus faible, c'est-à-dire, dans l'odre d'apparition de départ de gauche à droite
    :param abcd: bloc de 128 bits
    :return: 4 blocs de 32 bits a, b, c, d tel que abcd soit le bloc de départ
    """
    a = (abcd >> 96) & 0xFFFFFFFF
    b = (abcd >> 64) & 0xFFFFFFFF
    c = (abcd >> 32) & 0xFFFFFFFF
    d = abcd & 0xFFFFFFFF
    return a, b, c, d


def extract_32bit_bloc_from_256(abcdefgh):
    """
    Cette fonction décompose un bloc de 256 bits en 8 blocs de 32bits. Les blocs de sortie sont sont ordonnées
    du plus fort au plus faible, c'est-à-dire, dans l'odre d'apparition de départ de gauche à droite
    :param abcdefgh: bloc de 128 bits
    :return: 4 blocs de 32 bits a, b, c, d, e, f, g, h tel que abcdefgh soit le bloc de départ
    """
    a = (abcdefgh >> 224) & 0xFFFFFFFF
    b = (abcdefgh >> 192) & 0xFFFFFFFF
    c = (abcdefgh >> 160) & 0xFFFFFFFF
    d = (abcdefgh >> 128) & 0xFFFFFFFF
    e = (abcdefgh >> 96) & 0xFFFFFFFF
    f = (abcdefgh >> 64) & 0xFFFFFFFF
    g = (abcdefgh >> 32) & 0xFFFFFFFF
    h = abcdefgh & 0xFFFFFFFF
    return a, b, c, d, e, f, g, h


def build_256_bit_bloc_from_32_bit_blocs(a, b, c, d, e, f, g, h):
    """
    Cette fonction assemble des blocs de 32bits en un seul bloc de 256 bit. Les blocs en paramètres sont ordonnées
    du plus fort au plus faible, c'est-à-dire, dans l'odre d'apparition final de gauche à droite
    :param a: 1er bloc de 32bits
    :param b: 2ème bloc de 32bits
    :param c: 3ème bloc de 32 bits
    :param d: 4ème bloc de 32bits
    :param e: 5ème bloc de 32bits
    :param f: 6ème bloc de 32bits
    :param g: 7ème bloc de 32 bits
    :param h: 8ème bloc de 32bits
    :return: un bloc de 128 bits correspondant à l'ordre 'abcdefgh'
    """
    rs = (
            (a << 224) | (b << 192) | (c << 160) | (d << 128) |
            (e << 96) | (f << 64) | (g << 32) | h
    )
    return rs


def extract_8bit_blocs_from_32(abcd):
    """
    Cette fonction décompose un bloc de 32 bits en 4 blocs de 8bits. Les blocs de sortie sont sont ordonnées
    du plus fort au plus faible, c'est-à-dire, dans l'odre d'apparition de départ de gauche à droite
    :param abcd: bloc de 32 bits
    :return: 4 blocs de 8 bits a, b, c, d tel que abcd soit le bloc de départ
    """
    a = (abcd >> 24) & 0xFF
    b = (abcd >> 16) & 0xFF
    c = (abcd >> 8) & 0xFF
    d = abcd & 0xFF

    return a, b, c, d


def shift_left(data, input_size, n_bit):
    """
    Cette fonction doit être capable de barrel-shifter vers la gauche de n_bit éléments
    l'argument data de taille input_size
    :param data: L'entier à shifter.
    :param input_size: La taille en bits de data.
    :param n_bit: nombre de bit à shifter
    :return: L'entier data shifté de n-bit vers la gauche
    """
    n_bit = n_bit % input_size

    rs = (data << n_bit) | (data >> (input_size - n_bit))

    rs = rs & (2 ** input_size) - 1

    return rs
