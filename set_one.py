"""
https://cryptopals.com/sets/1
"""

import base64
import binascii
from Crypto.Cipher import AES


CHAR_FREQ_MAP = {
    'english': 'ETAOIN SHRDLU'
}


def _xor_two_byte_strings(bytes_1, bytes_2):
    return bytes(x ^ y for x, y in zip(bytes_1, bytes_2))


def _score_char_freq(string_to_score: bytes, language: str='english'):
    """Higher score means it's more likely to belong the given language"""
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


def encrypt_repeating_key_xor(plaintext_bytes: bytes, key: str):
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

def break_repeating_key_xor(encrypted_bytes: bytes):
    likely_keysizes = _determine_likely_keysizes(encrypted_bytes, 2, 40, 8)
    options = []
    for keysize in likely_keysizes[:3]:
        options.append(_transpose_and_xor_blocks(encrypted_bytes, keysize[0]))

    high_score = (0, None)
    for option in options:
        score = _score_char_freq(option)
        if score > high_score[0]:
            high_score = (score, option)

    return high_score[1]


def decrypt_aes_with_ecb(encrypted_bytes: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(encrypted_bytes)


def _transpose_and_xor_blocks(encrypted_bytes, keysize):
    transposed_blocks = [[] for x in range(keysize)]
    for i in range(len(encrypted_bytes)):
        block_index = i % keysize
        transposed_blocks[block_index].append(encrypted_bytes[i])
    original_key = []
    for block in transposed_blocks:
        block_as_bytes = ''.join([chr(x) for x in block]).encode('utf8')
        original_key.append(decrypt_xor_cipher(block_as_bytes)[0])
    plaintext = encrypt_repeating_key_xor(encrypted_bytes, ''.join(original_key))
    return binascii.unhexlify(plaintext)


def _determine_likely_keysizes(encrypted_bytes: bytes,
                               min_keysize: int,
                               max_keysize: int,
                               blocks_to_sample: int) -> list:
    keysize_distances = {}
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
    return likely_keysizes
