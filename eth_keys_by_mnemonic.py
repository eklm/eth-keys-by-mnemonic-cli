from mnemonic import Mnemonic
from bip32 import BIP32
import argparse
from sha3 import keccak_256
from coincurve import PublicKey
import sys

parser = argparse.ArgumentParser(description='Print eth keys with mnemonic (bip32,bip39)')
parser.add_argument('--derivation-path', help='bip32 derivation path', required=True)
args = parser.parse_args()

mnemonic = input("Enter mnemonic:").strip()

m = Mnemonic("english")
if not m.check(mnemonic):
    raise Exception("Mnemonic is incorrect")

seed = m.to_seed(mnemonic, "")

bip32 = BIP32.from_seed(seed)
pk = bip32.get_pubkey_from_path(args.derivation_path)
sk = bip32.get_privkey_from_path(args.derivation_path)

if len(pk) != 64:
    pk = PublicKey(pk).format(False)[1:]

h = keccak_256()
h.update(pk)
pk_hash = h.digest()

addr = f"0x{pk_hash[-20:].hex()}"
print(f"Your address is {addr}.")
print(f"Your private key is 0x{sk.hex()}")
