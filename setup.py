#!/usr/bin/env python
from setuptools import (
    find_packages,
    setup,
)

extras_require = {
    "dev": [
        "build>=0.9.0",
        "bump_my_version>=0.19.0",
        "ipython",
        "mypy==1.10.0",
        "pre-commit>=3.4.0",
        "tox>=4.0.0",
        "twine",
        "wheel",
    ],
    "docs": [
        "towncrier>=24,<25",
    ],
    "test": [
        "pytest>=7.0.0",
        "pytest-xdist>=2.4.0",
    ],
}

extras_require["dev"] = (
    extras_require["dev"] + extras_require["docs"] + extras_require["test"]
)


with open("./README.md") as readme:
    long_description = readme.read()


setup(
    name="eth-keyfile",
    # *IMPORTANT*: Don't manually change the version here. Use `make bump`, as described in readme
    version="0.9.0",
    description=(
        "eth-keyfile: A library for handling the encrypted keyfiles used to store "
        "ethereum private keys"
    ),
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="The Ethereum Foundation",
    author_email="snakecharmers@ethereum.org",
    url="https://github.com/ethereum/eth-keyfile",
    include_package_data=True,
    install_requires=[
        "eth-keys>=0.4.0",
        "eth-utils>=2",
        "py_ecc>=5.2.0",
        "pycryptodome>=3.6.6,<4",
    ],
    python_requires=">=3.8, <4",
    extras_require=extras_require,
    py_modules=["eth_keyfile"],
    license="MIT",
    zip_safe=False,
    keywords="ethereum",
    packages=find_packages(exclude=["scripts", "scripts.*", "tests", "tests.*"]),
    package_data={"eth_keyfile": ["py.typed"]},
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
)
