import codecs
import base64


CHAR_FREQ_MAP = {
    'english': 'ETAOIN SHRDLU'
}

def str_to_hex_bytes(hex_str: str):
    return codecs.decode(hex_str, 'hex')


def hex_to_base64(hex_str: str):
    hex_bytes = codecs.decode(hex_str, 'hex')
    b64_bytes = base64.b64encode(hex_bytes)
    return b64_bytes.decode()


def xor_two_hex_byte_strings(hex_bytes_1, hex_bytes_2):
    return bytes(x ^ y for x, y in zip(hex_bytes_1, hex_bytes_2))


def xor_two_strings(hex_str1: str, hex_str2: str):
    hex_bytes_1 = str_to_hex_bytes(hex_str1)
    hex_bytes_2 = str_to_hex_bytes(hex_str2)
    xored_bytes = xor_two_hex_byte_strings(hex_bytes_1, hex_bytes_2)
    hex_str = codecs.encode(xored_bytes, 'hex').decode('utf8')
    return hex_str


def decrypt_xor_cipher(hex_str: str):
    hex_bytes_1 = str_to_hex_bytes(hex_str)
    decrypted_scores = []
    for char in range(256):
        char = chr(char)
        repeated_cypher = (char * len(hex_bytes_1)).encode('utf8')
        decrypted_bytes = xor_two_hex_byte_strings(
            hex_bytes_1,
            repeated_cypher
        )
        decrypted_scores.append(
            (char, score_char_freq(decrypted_bytes), decrypted_bytes, hex_str)
        )
    sorted_scores = sorted(decrypted_scores, key=lambda x: x[1])
    return sorted_scores[-1]

def detect_single_character_xor(list_of_hex_str: list):
    decrypted_scores = []
    for string in list_of_hex_str:
        decrypted_scores.append(decrypt_xor_cipher(string))
    sorted_scores = sorted(decrypted_scores, key=lambda x: x[1])
    return sorted_scores[-1]

def score_char_freq(string_to_score: str, language: str='english'):
    score = 0
    language_char_freq = CHAR_FREQ_MAP[language] + CHAR_FREQ_MAP[language].lower()
    for char in string_to_score:
        if chr(char) in language_char_freq:
            score += 1
    return score
