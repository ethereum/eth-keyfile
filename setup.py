#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os

from setuptools import (
    setup,
    find_packages,
)


DIR = os.path.dirname(os.path.abspath(__file__))


setup(
    name='eth-keyfile',
    # *IMPORTANT*: Don't manually change the version here. Use the 'bumpversion' utility.
    version='0.4.0',
    description=(
        "A library for handling the encrypted keyfiles used to store ethereum "
        "private keys."
    ),
    long_description_markdown_filename='README.md',
    author='Piper Merriam',
    author_email='pipermerriam@gmail.com',
    url='https://github.com/ethereum/eth-keyfile',
    include_package_data=True,
    install_requires=[
        "eth-utils>=0.5.0",
        "eth-keys>=0.1.0-beta.3",
        "cytoolz>=0.8.2",
        "pycryptodome>=3.4.7",
    ],
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
