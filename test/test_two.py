import os
import base64
import set_one
import set_two
from test.data import set_two as set_two_data
from nose import tools


CUR_DIR = os.path.dirname(os.path.realpath(__file__))


def test_pad_with_pkcs7():
    inp = b'YELLOW SUBMARINE'
    expected = b'YELLOW SUBMARINE\x04\x04\x04\x04'
    actual = set_two.pad_with_pkcs7(inp, 20)
    tools.eq_(actual, expected)


def test_encrypt_with_ecb():
    inp = b'BLUE MOON'
    key = b'YELLOW SUBMARINE'
    encrypted = set_two.encrypt_aes_with_ecb(inp, key)
    actual = set_one.decrypt_aes_with_ecb(encrypted, key)
    expected = inp
    tools.eq_(actual, expected)

def test_encrypt_aes_with_cbc():
    inp = b'IM ROCKING THE SUBURBS, JUST LIKE MICHAEL JACKSON DID'
    key = b'YELLOW SUBMARINE'
    iv = b'\x00' * len(key)
    encrypted = set_two.encrypt_aes_with_cbc(inp, key, iv)
    actual = set_two.decrypt_aes_with_cbc(encrypted, key, iv)
    expected = inp
    tools.eq_(actual, expected)

def test_decrypt_aes_with_cbc():
    with open('{}/data/set_two_encrypted_cbc.txt'.format(CUR_DIR), 'r') as handle:
        inp = handle.read()
        inp = base64.b64decode(inp)
    key = b'YELLOW SUBMARINE'
    iv = b'\x00' * len(key)
    actual = set_two.decrypt_aes_with_cbc(inp, key, iv)
    expected = set_two_data.get_funky_lyrics()
    tools.eq_(actual, expected)
