eth-keyfile v0.9.0-beta.1 (2024-11-25)
--------------------------------------

Breaking Changes
~~~~~~~~~~~~~~~~

- Update type of ``password`` arg to be ``bytes`` instead of ``str``, bump to ``mypy==1.10.0`` and have it run with all local deps installed (`#55 <https://github.com/ethereum/eth-keyfile/issues/55>`__)


Features
~~~~~~~~

- Add the ability to generate v4 keyfiles in accordance with EIP-2335 (`#56 <https://github.com/ethereum/eth-keyfile/issues/56>`__)
- Create new ``EthKeyfileException`` and replace currently-used exceptions with ``EthKeyfile`` versions to allow more granular exception handling (`#58 <https://github.com/ethereum/eth-keyfile/issues/58>`__)


eth-keyfile v0.8.1 (2024-04-23)
-------------------------------

Internal Changes - for eth-keyfile Contributors
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Merge template updates, notably adding python 3.12 support (`#52 <https://github.com/ethereum/eth-keyfile/issues/52>`__)


Miscellaneous Changes
~~~~~~~~~~~~~~~~~~~~~

- `#53 <https://github.com/ethereum/eth-keyfile/issues/53>`__


eth-keyfile v0.8.0 (2024-02-28)
-------------------------------

Features
~~~~~~~~

- Add decode keyfile json v4 (`#42 <https://github.com/ethereum/eth-keyfile/issues/42>`__)


eth-keyfile v0.7.0 (2023-12-06)
-------------------------------

Breaking Changes
~~~~~~~~~~~~~~~~

- Use correct default parameters for ``scrypt`` (`#39 <https://github.com/ethereum/eth-keyfile/issues/39>`__)
- Drop python 3.7 support (`#47 <https://github.com/ethereum/eth-keyfile/issues/47>`__)


Features
~~~~~~~~

- Checksum address when creating a keyfile (`#35 <https://github.com/ethereum/eth-keyfile/issues/35>`__)


Internal Changes - for eth-keyfile Contributors
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Merge project template updates, including using pre-commit for linting. Add typing. (`#47 <https://github.com/ethereum/eth-keyfile/issues/47>`__)


0.6.1
-----

- Remove deprecated `setuptools-markdown` dependency (https://github.com/ethereum/eth-keyfile/pull/37)
- Use twine to upload package to pypi

0.6.0
-----

- Mitigate timing attack (https://github.com/ethereum/eth-keyfile/pull/13)
- Fix typo in README (https://github.com/ethereum/eth-keyfile/pull/14)
- Migrate to CircleCI (https://github.com/ethereum/eth-keyfile/pull/22)
- Allow salt size specification on keyfile creation
(https://github.com/ethereum/eth-keyfile/pull/25)
- Drop Python 3.5 and 3.6 support, Add Python 3.8-3.10 support and update corresponding dependencies (https://github.com/ethereum/eth-keyfile/pull/33)


0.4.0
-----

- Rename repo and module to `eth-keyfile`
- Added deprecation warning for python 2


0.3.0
-----

- Add `address` key to generated keyfile JSON


0.2.0
-----

- Remove `0x` prefixes from hex values in generated json.


0.1.0
-----

Initial release
