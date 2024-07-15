from argparse import ArgumentParser
from hashlib import sha256
from pathlib import Path
import base64
import re

from Crypto.Cipher import AES

# based on https://github.com/gquere/pwn_jenkins/blob/master/offline_decryption/jenkins_offline_decrypt.py

DECRYPTION_MAGIC = b'::::MAGIC::::'


class DecryptionError(Exception):
    pass


def get_confidentiality_key(master_key_path: Path, hudson_secret_path: Path) -> bytes:

    # the master key is random bytes stored in text
    with open(master_key_path, 'r') as f:
        master_key = f.read().encode('utf-8')

    # the hudson secret is bytes encrypted using a key derived from the master key
    with open(hudson_secret_path, 'rb') as f:
        hudson_secret = f.read()

    # sanitize keys if copy or base64 introduced a newline
    if len(master_key)%2 != 0 and master_key[-1:] == b'\n':
        master_key = master_key[:-1]
    if len(hudson_secret)%2 != 0 and hudson_secret[-1:] == b'\n':
        hudson_secret = hudson_secret[:-1]

    return decrypt_confidentiality_key(master_key, hudson_secret)


def decrypt_confidentiality_key(master_key: bytes, hudson_secret: bytes) -> bytes:
    # the master key is hashed and truncated to 16 bytes due to US restrictions
    derived_master_key = sha256(master_key).digest()[:16]

    # the hudson key is decrypted using this derived key
    cipher_handler = AES.new(derived_master_key, AES.MODE_ECB)
    decrypted_hudson_secret = cipher_handler.decrypt(hudson_secret)

    # check if the key contains the magic
    if DECRYPTION_MAGIC not in decrypted_hudson_secret:
        raise DecryptionError('decrypted hudson secret does not contain magic bytes')

    # the hudson key is the first 16 bytes for AES128
    return decrypted_hudson_secret[:16]


# old secret encryption format in jenkins is plain AES ECB
def decrypt_secret_old_format(encrypted_secret: bytes, confidentiality_key: bytes) -> bytes:
    cipher_handler = AES.new(confidentiality_key, AES.MODE_ECB)
    decrypted_secret = cipher_handler.decrypt(encrypted_secret)

    if not DECRYPTION_MAGIC in decrypted_secret:
        raise DecryptionError('decrypted secret does not contain magic bytes')

    return decrypted_secret.split(DECRYPTION_MAGIC)[0]


# new encryption format in jenkins is AES CBC
def decrypt_secret_new_format(encrypted_secret: bytes, confidentiality_key: bytes) -> bytes:
    iv = encrypted_secret[9:9+16] # skip version + iv and data lengths
    cipher_handler = AES.new(confidentiality_key, AES.MODE_CBC, iv)
    decrypted_secret = cipher_handler.decrypt(encrypted_secret[9+16:])

    # remove PKCS#7 padding
    padding_value = decrypted_secret[-1]
    if padding_value > 16:
        return decrypted_secret

    secret_length = len(decrypted_secret) - padding_value

    return decrypted_secret[:secret_length]


def decrypt_secret(encoded_secret: str, confidentiality_key: bytes) -> str:
    if not encoded_secret:
        return ''

    encrypted_secret = base64.b64decode(encoded_secret)
    try:
        if encrypted_secret[0] == 1:
            decrypted_secret = decrypt_secret_new_format(encrypted_secret, confidentiality_key)
        else:
            decrypted_secret = decrypt_secret_old_format(encrypted_secret, confidentiality_key)
    except DecryptionError:
        return '{' + encoded_secret + '}'

    try:
        return decrypted_secret.decode('utf8')
    except UnicodeDecodeError:
        return base64.b64encode(decrypted_secret).decode('utf8')


def decrypt_credentials(content: str, confidentiality_key: bytes) -> str:
    pattern = re.compile(r'\{([^}]+)\}')
    return pattern.sub(lambda match: decrypt_secret(match.group(1), confidentiality_key), content)


def main() -> None:
    entrypoint = ArgumentParser()
    entrypoint.add_argument('masterkey', type=Path, metavar='MASTER_KEY_FILE')
    entrypoint.add_argument('hudsonsecret', type=Path, metavar='HUDSON_SECRET_FILE')
    entrypoint.add_argument('credential', nargs='+', type=Path, metavar='CREDENTIAL_FILE')
    opts = entrypoint.parse_args()

    confidentiality_key = get_confidentiality_key(opts.masterkey, opts.hudsonsecret)
    for encrypted_path in opts.credential:
        with open(encrypted_path, 'r') as file:
            encrypted_content = file.read()
        decrypted_content = decrypt_credentials(encrypted_content, confidentiality_key)
        decrypted_path = encrypted_path.with_suffix(f'.decrypted{encrypted_path.suffix}')
        print(decrypted_path)
        with open(decrypted_path, 'w') as file:
            file.write(decrypted_content)


if __name__ == '__main__':
    main()
