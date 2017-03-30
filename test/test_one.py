import set_one
from nose import tools
from test.data import set_one as set_one_data


def test_hex_to_base64():
    inp = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    actual = set_one.hex_to_base64(inp)
    expected = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    tools.eq_(actual, expected)

def test_xor_two_strings():
    inp1 = '1c0111001f010100061a024b53535009181c'
    inp2 = '686974207468652062756c6c277320657965'
    actual = set_one.xor_two_strings(inp1, inp2)
    expected = '746865206b696420646f6e277420706c6179'
    tools.eq_(actual, expected)

def test_single_byte_xor_cipher():
    inp = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    actual = set_one.decrypt_xor_cipher(inp)[0]
    expected = 'X'
    tools.eq_(actual, expected)

def test_detect_byte_xor_cipher():
    inputs = set_one_data.get_list_of_possible_single_char_xor()
    actual = set_one.detect_single_character_xor(inputs)[3]
    expected = '7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f'
    tools.eq_(actual, expected)

def test_encrypt_with_repeating_key_xor():
    inp = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    actual = set_one.encrypt_repeating_key_xor(inp, 'ICE')
    expected = b'0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
    tools.eq_(actual, expected, '\n{}\n{}'.format(actual, expected))
