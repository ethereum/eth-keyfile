#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import (
    setup,
    find_packages,
)


deps = {
    'keyfile': [
        "eth-utils>=1.3.0,<2",
        "eth-keys>=0.2.1,<0.4.0",
        "pycryptodome>=3.6.6,<4",
    ],
    'test': [
        "pytest>=3.6,<3.7",
    ],
    'lint': [
        "flake8==3.5.0",
    ],
    'dev': [
        "bumpversion>=0.5.3,<1",
        "wheel",
        "setuptools>=36.2.0",
        # Fixing this dependency due to: pytest 3.6.4 has requirement pluggy<0.8,>=0.5, but you'll have pluggy 0.8.0 which is incompatible.
        "pluggy==0.7.1",
        # Fixing this dependency due to: requests 2.20.1 has requirement idna<2.8,>=2.5, but you'll have idna 2.8 which is incompatible.
        "idna==2.7",
        # idna 2.7 is not supported by requests 2.18
        "requests>=2.20,<3",
        "tox>=2.7.0",
        "twine",
    ],
}

deps['dev'] = (
    deps['keyfile'] +
    deps['dev'] +
    deps['test'] +
    deps['lint']
)


install_requires = deps['keyfile']

setup(
    name='eth-keyfile',
    # *IMPORTANT*: Don't manually change the version here. Use the 'bumpversion' utility.
    version='0.5.1',
    description=(
        "A library for handling the encrypted keyfiles used to store ethereum "
        "private keys."
    ),
    long_description_markdown_filename='README.md',
    author='Piper Merriam',
    author_email='pipermerriam@gmail.com',
    url='https://github.com/ethereum/eth-keyfile',
    include_package_data=True,
    install_requires=install_requires,
    extras_require=deps,
    setup_requires=['setuptools-markdown'],
    py_modules=['eth_keyfile'],
    license="MIT",
    zip_safe=False,
    keywords='ethereum',
    packages=find_packages(exclude=["tests", "tests.*"]),
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],
)
