#!/usr/bin/env python3
"""Regenerate mayhem/fixtures/ and the per-target seed files (run once by hand; outputs are committed).

Every TPM structure here is hand-marshalled big-endian per the TPM 2.0 spec (Part 2), so no TPM is
needed: RSA-2048 / NIST P-256 public areas, a TSS2 PRIVATE KEY PEM, quote/certify TPMS_ATTEST blobs,
a context file, and the RSA private key / secret the offline makecredential/duplicate targets use.
"""
import os, struct, sys, hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization

out = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
u16 = lambda v: struct.pack(">H", v); u32 = lambda v: struct.pack(">I", v); u64 = lambda v: struct.pack(">Q", v)
tpm2b = lambda b: u16(len(b)) + b

def w(rel, data):
    p = os.path.join(out, rel); os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "wb").write(data)

# Deterministic keys: fixed small-ish primes are not needed; keys are generated once and committed.
rk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ek = ec.generate_private_key(ec.SECP256R1())
n = rk.public_key().public_numbers().n.to_bytes(256, "big")
pt = ek.public_key().public_numbers()

ATTR_STORAGE = 0x00030072  # fixedTPM|fixedParent|sensitiveDataOrigin|userWithAuth|restricted|decrypt
AES128CFB = u16(0x0006) + u16(128) + u16(0x0043)
rsa_tmpt = u16(0x0001) + u16(0x000b) + u32(ATTR_STORAGE) + tpm2b(b"") + AES128CFB + u16(0x0010) + u16(2048) + u32(0) + tpm2b(n)
ecc_tmpt = (u16(0x0023) + u16(0x000b) + u32(ATTR_STORAGE) + tpm2b(b"") + AES128CFB + u16(0x0010) + u16(0x0003) + u16(0x0010)
            + tpm2b(pt.x.to_bytes(32, "big")) + tpm2b(pt.y.to_bytes(32, "big")))
rsa_pub, ecc_pub = tpm2b(rsa_tmpt), tpm2b(ecc_tmpt)
keyed_hash = u16(0x0008) + u16(0x000b) + u32(0x00040072 & ~0x00020000) + tpm2b(b"") + u16(0x0010) + tpm2b(hashlib.sha256(b"seal").digest())

# TPMS_ATTEST: quote (PCR0 sha256) and certify.
name = u16(0x000b) + hashlib.sha256(rsa_tmpt).digest()
hdr = lambda st: u32(0xff544347) + u16(st) + tpm2b(name) + tpm2b(b"nonce") + u64(123456) + u32(1) + u32(2) + b"\x01" + u64(0x2011000000000)
quote = hdr(0x8018) + u32(1) + u16(0x000b) + b"\x03\x01\x00\x00" + tpm2b(hashlib.sha256(b"\x00" * 32).digest())
certify = hdr(0x8017) + tpm2b(name) + tpm2b(name)
# TPM2B_ATTEST wrapper as written by `tpm2 quote -m` is the raw TPMS_ATTEST; checkquote reads that.

# Context file (lib/files.c): BADCC0DE magic, version 1, hierarchy, savedHandle, sequence, TPM2B blob.
context = u32(0xBADCC0DE) + u32(1) + u32(0x40000001) + u32(0x80000000) + u64(7) + tpm2b(os.urandom(64))

def der_len(l):
    return bytes([l]) if l < 128 else (bytes([0x81, l]) if l < 256 else bytes([0x82]) + u16(l))
def der(tag, body): return bytes([tag]) + der_len(len(body)) + body
tss_der = der(0x30, der(0x06, bytes.fromhex("678105 0a0103".replace(" ", ""))) + der(0xa0, der(0x01, b"\xff"))
              + der(0x02, b"\x40\x00\x00\x01") + der(0x04, rsa_pub) + der(0x04, tpm2b(os.urandom(48))))
import base64
b64 = base64.encodebytes(tss_der).decode().replace("\n", "")
tss_pem = ("-----BEGIN TSS2 PRIVATE KEY-----\n" + "\n".join(b64[i:i+64] for i in range(0, len(b64), 64))
           + "\n-----END TSS2 PRIVATE KEY-----\n").encode()

# TPMT_SIGNATURE (RSASSA/SHA256) over nothing in particular: checkquote parses the PCR file before
# verifying, so a well-formed but wrong signature is enough to reach the PCR/eventlog parsers.
sig = u16(0x0014) + u16(0x000b) + tpm2b(os.urandom(256))

fx = "fixtures"
w(f"{fx}/rsa-key.pem", rk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
w(f"{fx}/rsa-pub.pem", rk.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
w(f"{fx}/secret.bin", b"0123456789abcdef0123456789abcdef")
w(f"{fx}/quote.msg", quote)
w(f"{fx}/quote.sig", sig)

for t, files in {
    "print-attest": {"quote.bin": quote, "certify.bin": certify},
    "print-public": {"rsa.pub": rsa_pub, "ecc.pub": ecc_pub, "keyedhash.pub": tpm2b(keyed_hash)},
    "print-tpmt-public": {"rsa.tmpt": rsa_tmpt, "ecc.tmpt": ecc_tmpt},
    "print-tssprivkey": {"rsa.tss": tss_pem},
    "print-context": {"ctx.bin": context},
    "makecredential": {"rsa.pub": rsa_pub, "ecc.pub": ecc_pub},
    "duplicate": {"rsa.pub": rsa_pub, "ecc.pub": ecc_pub},
    "tr-encode": {"rsa.pub": rsa_pub, "ecc.pub": ecc_pub},
}.items():
    for fn, data in files.items():
        w(f"{t}/testsuite/{fn}", data)

# checkquote -f: the tool's own PCR file layout (tools/misc/tpm2_checkquote.c
# parse_selection_data_from_file): raw little-endian TPML_PCR_SELECTION (4 + 16 x 8 bytes), a u32
# bank count, then raw TPML_DIGESTs (4 + 8 x 66 bytes). One sha256 bank selecting PCR0.
sel = struct.pack("<I", 1) + struct.pack("<HB4s", 0x000b, 3, b"\x01\x00\x00\x00") + b"\x00" + b"\x00" * 8 * 15
digs = struct.pack("<I", 1) + struct.pack("<H", 32) + hashlib.sha256(b"pcr0").digest() + b"\x00" * 32 + b"\x00" * 66 * 7
w("checkquote/testsuite/pcr0-sha256.pcrs", sel + struct.pack("<I", 1) + digs)
