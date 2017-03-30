"""
https://cryptopals.com/sets/1
"""

import codecs
import base64


CHAR_FREQ_MAP = {
    'english': 'ETAOIN SHRDLU'
}


def _hex_str_to_hex_bytes(hex_str: str):
    return codecs.decode(hex_str, 'hex')


def _hex_bytes_to_hex_str(hex_bytes: str):
    return codecs.encode(hex_bytes, 'hex').decode('utf8')


def _xor_two_byte_strings(bytes_1, bytes_2):
    return bytes(x ^ y for x, y in zip(bytes_1, bytes_2))


def _score_char_freq(string_to_score: str, language: str='english'):
    score = 0
    language_char_freq = CHAR_FREQ_MAP[language] + CHAR_FREQ_MAP[language].lower()
    for char in string_to_score:
        if chr(char) in language_char_freq:
            score += 1
    return score


def hex_to_base64(hex_str: str):
    hex_bytes = codecs.decode(hex_str, 'hex')
    b64_bytes = base64.b64encode(hex_bytes)
    return b64_bytes.decode()


def xor_two_strings(hex_str1: str, hex_str2: str):
    hex_bytes_1 = _hex_str_to_hex_bytes(hex_str1)
    hex_bytes_2 = _hex_str_to_hex_bytes(hex_str2)
    xored_bytes = _xor_two_byte_strings(hex_bytes_1, hex_bytes_2)
    hex_str = _hex_bytes_to_hex_str(xored_bytes)
    return hex_str


def decrypt_xor_cipher(hex_str: str):
    hex_bytes_1 = _hex_str_to_hex_bytes(hex_str)
    decrypted_scores = []
    for char in range(256):
        char = chr(char)
        repeated_cypher = (char * len(hex_bytes_1)).encode('utf8')
        decrypted_bytes = _xor_two_byte_strings(
            hex_bytes_1,
            repeated_cypher
        )
        decrypted_scores.append(
            (char, _score_char_freq(decrypted_bytes), decrypted_bytes, hex_str)
        )
    sorted_scores = sorted(decrypted_scores, key=lambda x: x[1])
    return sorted_scores[-1]


def detect_single_character_xor(list_of_hex_str: list):
    decrypted_scores = []
    for string in list_of_hex_str:
        decrypted_scores.append(decrypt_xor_cipher(string))
    sorted_scores = sorted(decrypted_scores, key=lambda x: x[1])
    return sorted_scores[-1]


def encrypt_repeating_key_xor(plaintext: str, key: str):
    plaintext_bytes = plaintext.encode('utf8')
    key_bytes = key.encode('utf8')
    encrypted_bytes = []
    for i in range(len(plaintext_bytes)):
        xored_byte = key_bytes[i % len(key_bytes)] ^ plaintext_bytes[i]
        encrypted_bytes.append(xored_byte)
    return codecs.encode(bytes(encrypted_bytes), 'hex')


def compute_hamming_distance(str_one: str, str_two: str):
    diff = _xor_two_byte_strings(
        str_one.encode('utf8'),
        str_two.encode('utf8')
    )
    raw_bits = [format(x, 'b') for x in diff]
    distance = sum([x.count('1') for x in raw_bits])
    return distance
