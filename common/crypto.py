import os
def rc4(data: bytes, key: bytes) -> bytes:

    S = list(range(256))
    j = 0
    out = bytearray()

    # KSA
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    # PRGA
    i = j = 0
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])

    return bytes(out)


def encrypt_key(key: bytes) -> bytes:

    xor_val = os.urandom(1)[0]
    encr_key = os.urandom(1)[0]
    print("hint byte:", hex(xor_val))
    hint_byte = xor_val

    full_key = bytearray([hint_byte]) + key
    encrypted_key = bytearray(b ^ encr_key for b in full_key)
    return bytes([hint_byte]) + encrypted_key