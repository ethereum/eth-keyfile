import json
import os

from eth_utils.toolz import (
    assoc,
)
import pytest

import eth_keyfile

FIXTURES_FILE_PATH = os.path.join(
    os.path.dirname(os.path.dirname((eth_keyfile.__file__))),
    "fixtures",
    "KeyStoreTests",
    "basic_tests.json",
)

MEW_KEYFILE = {
    "json": {
        "Crypto": {
            "cipher": "aes-128-ctr",
            "cipherparams": {
                "iv": "7e7b02d2b4ef45d6c98cb885e75f48d5",
            },
            "ciphertext": "a7a5743a6c7eb3fa52396bd3fd94043b79075aac3ccbae8e62d3af94db00397c",  # noqa: E501
            "kdf": "scrypt",
            "kdfparams": {
                "dklen": 32,
                "n": 8192,
                "p": 1,
                "r": 8,
                "salt": "247797c7a357b707a3bdbfaa55f4c553756bca09fec20ddc938e7636d21e4a20",  # noqa: E501
            },
            "mac": "5a3ba5bebfda2c384586eda5fcda9c8397d37c9b0cc347fea86525cf2ea3a468",
        },
        "address": "0b6f2de3dee015a95d3330dcb7baf8e08aa0112d",
        "id": "3c8efdd6-d538-47ec-b241-36783d3418b9",
        "version": 3,
    },
    "password": "moomoocow",
    "priv": "21eac69b9a52f466bfe9047f0f21c9caf3a5cdaadf84e2750a9b3265d450d481",
}


with open(FIXTURES_FILE_PATH) as fixtures_file:
    BASE_KEYFILE_FIXTURES = json.load(fixtures_file)


KEYFILE_FIXTURES = assoc(BASE_KEYFILE_FIXTURES, "MEW_generated_keyfile", MEW_KEYFILE)


@pytest.fixture(params=KEYFILE_FIXTURES.keys())
def keyfile_data(request):
    return KEYFILE_FIXTURES[request.param]
