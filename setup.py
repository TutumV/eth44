from setuptools import setup, find_packages

setup(
    name="eth44",
    version="1.0.0",
    description="Python code to generate Ethereum addresses from a hierarchical deterministic wallet according to the BIP44 standard.",
    author="Michail Brynard",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "rlp",
        "eth-utils",
        "pycrypto",
        "pycryptodome",
        "base58",
        "mnemonic",
    ],
)
