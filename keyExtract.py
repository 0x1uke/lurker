#!/usr/bin/env python3
#
# Modified from Fox-IT's dump_beacon_keys.py to dump public key
# https://github.com/fox-it/dissect.cobaltstrike/blob/main/scripts/dump_beacon_keys.py
#
# This script dumps the RSA Private Key from `.cobaltstrike.beacon_keys`.
#
# It requires the javaobj module, install it with:
#
#   $ pip install javaobj-py3
#
import javaobj
import base64

key = javaobj.loads(open(".cobaltstrike.beacon_keys", "rb").read())
pubkey_der = bytes(c & 0xFF for c in key.array.value.publicKey.encoded)

print("-----BEGIN PUBLIC KEY-----")
print(base64.encodebytes(pubkey_der).strip().decode())
print("-----END PUBLIC KEY-----")