def pad_with_pkcs7(plaintext_bytes: bytes, desired_size: int):
    start_size = len(plaintext_bytes)
    pad_bytes = desired_size - start_size 
    pad_bytes = (chr(pad_bytes) * pad_bytes).encode('utf8')
    return plaintext_bytes + pad_bytes
