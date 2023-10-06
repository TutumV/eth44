from dataclasses import dataclass

from eth44.crypto import HDKey as HDKeyEthereum
from eth44.crypto import HDPrivateKey

DEFAULT_HD_PATH = "m/44'/60'/0'"


@dataclass
class Wallet:
    address: str
    private_key: str
    leaf: int
    account: int
    mnemonic: str


def create_wallet(mnemonic: str, account: int = 0, leaf: int = 0) -> Wallet:
    master_key = HDPrivateKey.master_key_from_mnemonic(mnemonic=mnemonic)
    root_key = HDKeyEthereum.from_path(master_key, DEFAULT_HD_PATH)
    keys = HDKeyEthereum.from_path(
        root_key=root_key[-1], path='{account}/{leaf}'.format(account=account, leaf=leaf)
    )
    private_key = keys[-1]
    address = private_key.public_key.address()
    return Wallet(
        address=address,
        private_key=private_key._key.to_hex(),
        leaf=leaf,
        account=account,
        mnemonic=mnemonic
    )
