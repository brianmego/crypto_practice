import set_one
from Crypto.Cipher import AES


def pad_with_pkcs7(plaintext_bytes: bytes, desired_size: int):
    start_size = len(plaintext_bytes)
    pad_bytes = desired_size - start_size 
    pad_bytes = (chr(pad_bytes) * pad_bytes).encode('utf8')
    return plaintext_bytes + pad_bytes

def encrypt_aes_with_ecb(plaintext_bytes: bytes, key: bytes):
    padded_bytes = pad_with_pkcs7(plaintext_bytes, len(key))
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(padded_bytes)

def encrypt_aes_with_cbc(plaintext_bytes: bytes, key: bytes, iv: bytes):
    keysize = len(key)
    num_of_blocks = int(len(plaintext_bytes) / keysize)
    if len(plaintext_bytes) % keysize != 0:
        num_of_blocks += 1
    prev_block = iv
    encrypted_arr = []
    for counter in range(num_of_blocks):
        start_index = counter * keysize
        end_index = (counter + 1) * keysize
        block = plaintext_bytes[start_index:end_index]
        xor_block = set_one.xor_two_byte_strings(block, prev_block)
        encrypted_block = encrypt_aes_with_ecb(xor_block, key)
        prev_block = encrypted_block
        encrypted_arr.extend(encrypted_block)
    return bytes(encrypted_arr)

def decrypt_aes_with_cbc(encrypted_bytes: bytes, key: bytes, iv: bytes):
    keysize = len(key)
    num_of_blocks = int(len(encrypted_bytes) / keysize)
    decrypted_arr = []
    for counter in range(num_of_blocks):
        start_index = (num_of_blocks - counter - 1) * keysize
        end_index = (num_of_blocks - counter) * keysize
        encrypted_block = encrypted_bytes[start_index:end_index]
        if counter < num_of_blocks - 1:
            prev_encrypted_block = encrypted_bytes[start_index - keysize: start_index]
        else:
            prev_encrypted_block = iv
        decrypted_block = set_one.decrypt_aes_with_ecb(encrypted_block, key)
        xor_block = set_one.xor_two_byte_strings(decrypted_block, prev_encrypted_block)
        decrypted_arr.append(xor_block)
    return b"".join(reversed(decrypted_arr))

        
