import set_two
from nose import tools

def test_pad_with_pkcs7():
    inp = b'YELLOW SUBMARINE'
    expected = b'YELLOW SUBMARINE\x04\x04\x04\x04'
    actual = set_two.pad_with_pkcs7(inp, 20)
    tools.eq_(actual, expected)
