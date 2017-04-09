"""
https://cryptopals.com/sets/1
"""

import base64
import binascii


CHAR_FREQ_MAP = {
    'english': 'ETAOIN SHRDLU'
}


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
    hex_bytes = binascii.a2b_hex(hex_str)
    b64_bytes = base64.b64encode(hex_bytes)
    return b64_bytes.decode()


def xor_two_strings(hex_str1: str, hex_str2: str):
    hex_bytes_1 = binascii.a2b_hex(hex_str1)
    hex_bytes_2 = binascii.a2b_hex(hex_str2)
    xored_bytes = _xor_two_byte_strings(hex_bytes_1, hex_bytes_2)
    hex_str = xored_bytes.hex()
    return hex_str


def decrypt_xor_cipher(hex_bytes: bytes):
    decrypted_scores = []
    for char in range(256):
        char = chr(char)
        repeated_cypher = (char * len(hex_bytes)).encode('utf8')
        decrypted_bytes = _xor_two_byte_strings(
            hex_bytes,
            repeated_cypher
        )
        decrypted_scores.append(
            (char, _score_char_freq(decrypted_bytes), decrypted_bytes, hex_bytes.hex())
        )
    sorted_scores = sorted(decrypted_scores, key=lambda x: x[1])
    return sorted_scores[-1]


def detect_single_character_xor(list_of_hex_str: list):
    decrypted_scores = []
    for string in list_of_hex_str:
        decrypted_scores.append(decrypt_xor_cipher(binascii.a2b_hex(string)))
    sorted_scores = sorted(decrypted_scores, key=lambda x: x[1])
    return sorted_scores[-1]


def encrypt_repeating_key_xor(plaintext: str, key: str):
    plaintext_bytes = plaintext.encode('utf8')
    key_bytes = key.encode('utf8')
    encrypted_bytes = []
    for i in range(len(plaintext_bytes)):
        xored_byte = key_bytes[i % len(key_bytes)] ^ plaintext_bytes[i]
        encrypted_bytes.append(xored_byte)
    return bytes(encrypted_bytes).hex()


def compute_hamming_distance(str_one: bytes, str_two: bytes):
    diff = _xor_two_byte_strings(
        str_one,
        str_two
    )
    raw_bits = [format(x, 'b') for x in diff]
    distance = sum([x.count('1') for x in raw_bits])
    return distance

def break_repeating_key_xor(encrypted_bytes):
    min_keysize = 2
    max_keysize = 40
    keysize_distances = {}
    blocks_to_sample = 8
    for i in range(min_keysize, max_keysize + 1):
        blocks = []
        for j in range(blocks_to_sample):
            blocks.append(encrypted_bytes[i * j:i * (j + 1)])
        distances = []
        for j in range(blocks_to_sample - 1):
            distances.append(compute_hamming_distance(blocks[j], blocks[j + 1]))
        average_distance = sum(distances) / len(distances)
        normalized_for_keysize = average_distance / i
        keysize_distances[i] = normalized_for_keysize
    likely_keysizes = sorted(keysize_distances.items(), key=lambda x: x[1])

