# TODO Push to cryptography project (https://github.com/pyca/cryptography/)

import base64
import binascii
from cryptography import utils
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
import os
from pathlib import Path
import six
import struct
import time


class InvalidToken(Exception):
    pass


_MAX_CLOCK_SKEW = 60


class Crypto(object):
    def __init__(self, key : bytes):
        backend = default_backend()

        key = base64.urlsafe_b64decode(key)
        if len(key) != 32:
            raise ValueError(
                "Key must be 32 url-safe base64-encoded bytes."
            )

        self._signing_key = key[:16]
        self._encryption_key = key[16:]
        self._backend = backend

    @classmethod
    def generate_key(cls) -> bytes:
        key = base64.urlsafe_b64encode(os.urandom(32))
        return key

    def encrypt(self, src : Path, dst : Path):
        current_time = int(time.time())
        nonce = os.urandom(16)
        encryptor = Cipher(
            algorithms.AES(self._encryption_key), modes.CTR(nonce), self._backend
        ).encryptor()

        basic_parts = (
            b"\x8a" + struct.pack(">Q", current_time) + nonce
        )
        h = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
        h.update(basic_parts)
        with open(src, 'rb') as s, open(dst, 'wb') as d:
            # Write the header
            d.write(basic_parts)
            # Write padded chunks of data
            for data in iter(lambda: s.read(4096), b""):
                ciphertext = encryptor.update(data)
                h.update(ciphertext)
                d.write(ciphertext)
            fin = encryptor.finalize()
            h.update(fin)
            d.write(fin)
            # Write HMAC
            hmac = h.finalize()
            d.write(hmac)

    def decrypt(self, src : Path, dst : Path, ttl=None):
        with open(src, 'rb') as h_src, open(dst, 'wb') as h_dst:
            # Prepare HMAC checking
            hmac = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
            # Get timestamp
            header = h_src.read(9)
            hmac.update(header)
            timestamp = self._get_timestamp(header)
            # Check timestamp
            current_time = int(time.time())
            if ttl is not None:
                if timestamp + ttl < current_time:
                    raise InvalidToken

                if current_time + _MAX_CLOCK_SKEW < timestamp:
                    raise InvalidToken
            # Get nonce
            nonce = h_src.read(16)
            hmac.update(nonce)
            decryptor = Cipher(
                algorithms.AES(self._encryption_key), modes.CTR(nonce), self._backend
            ).decryptor()
            # Decrypt ciphertext
            ciphertext_end = os.stat(src).st_size - 32
            while h_src.tell() < ciphertext_end:
                remains = ciphertext_end - h_src.tell()
                ciphertext_size = 4096 if remains >= 4096 else remains
                ciphertext = h_src.read(ciphertext_size)
                hmac.update(ciphertext)
                h_dst.write(decryptor.update(ciphertext))
            try:
                fin = decryptor.finalize()
                hmac.update(fin)
                h_dst.write(fin)
            except ValueError:
                raise InvalidToken
            # Check HMAC
            try:
                signature = h_src.read(32)
                hmac.verify(signature)
            except InvalidSignature:
                raise InvalidToken

    @staticmethod
    def _get_timestamp(data : bytes):
        if not data or six.indexbytes(data, 0) != 0x8a:
            raise InvalidToken

        try:
            timestamp, = struct.unpack(">Q", data[1:9])
        except struct.error:
            raise InvalidToken
        return timestamp
