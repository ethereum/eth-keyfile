from eth_utils import (
    decode_hex,
)

from eth_keyfile.keyfile import (
    create_keyfile_json,
    decode_keyfile_json,
)

PRIVATE_KEY = decode_hex(
    "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d"
)
PASSWORD = b"foo"


def test_pbkdf2_keyfile_creation():
    keyfile_json = create_keyfile_json(
        PRIVATE_KEY,
        password=PASSWORD,
        kdf="pbkdf2",
        iterations=1,
    )
    derived_private_key = decode_keyfile_json(keyfile_json, PASSWORD)
    assert derived_private_key == PRIVATE_KEY


def test_pbkdf2_keyfile_salt32_creation():
    keyfile_json = create_keyfile_json(
        PRIVATE_KEY,
        password=PASSWORD,
        kdf="pbkdf2",
        iterations=1,
        salt_size=32,
    )
    assert len(keyfile_json["crypto"]["kdfparams"]["salt"]) == 32 * 2
    derived_private_key = decode_keyfile_json(keyfile_json, PASSWORD)
    assert derived_private_key == PRIVATE_KEY


def test_scrypt_keyfile_creation():
    keyfile_json = create_keyfile_json(
        PRIVATE_KEY,
        password=PASSWORD,
        kdf="scrypt",
        iterations=2,
    )
    derived_private_key = decode_keyfile_json(keyfile_json, PASSWORD)
    assert derived_private_key == PRIVATE_KEY


def test_scrypt_keyfile_address():
    keyfile_json = create_keyfile_json(
        PRIVATE_KEY,
        password=PASSWORD,
        kdf="scrypt",
        iterations=2,
    )
    assert keyfile_json["address"] == "008AeEda4D805471dF9b2A5B0f38A0C3bCBA786b"
