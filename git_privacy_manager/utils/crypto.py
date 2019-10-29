# TODO Push to cryptography project (https://github.com/pyca/cryptography/)

import base64
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
import os
from pathlib import Path
import six
import struct
import time
from typing import Iterator


class InvalidToken(Exception):
    pass


_MAX_CLOCK_SKEW = 60


class Crypto(object):
    def __init__(self, key: bytes):
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

    def encrypt_file(self, src: Path, dst: Path):
        with open(src, 'rb') as s, open(dst, 'wb') as d:
            ciphertext = self.encrypt_stream(iter(lambda: s.read(4096), b''))
            for data in ciphertext:
                d.write(data)

    def encrypt_stream(self, src: Iterator[bytes]) -> Iterator[bytes]:
        current_time = int(time.time())
        nonce = os.urandom(16)
        encryptor = Cipher(
            algorithms.AES(self._encryption_key), modes.CTR(
                nonce), self._backend
        ).encryptor()

        basic_parts = (
            b"\x8a" + struct.pack(">Q", current_time) + nonce
        )
        h = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
        h.update(basic_parts)
        yield basic_parts
        # Write padded chunks of data
        for data in src:
            ciphertext = encryptor.update(data)
            h.update(ciphertext)
            yield ciphertext
        fin = encryptor.finalize()
        h.update(fin)
        yield fin
        # Write HMAC
        hmac = h.finalize()
        yield hmac

    def decrypt_file(self, src: Path, dst: Path, ttl=None):
        with open(src, 'rb') as s, open(dst, 'wb') as d:
            plaintext = self.decrypt_stream(
                iter(lambda: s.read(4096), b''), ttl)
            for data in plaintext:
                if data:
                    d.write(data)

    def decrypt_stream(self, src: Iterator[bytes], ttl=None) -> Iterator[bytes]:
        def check_header(data: bytes):
            # Check magic number
            if six.indexbytes(buffer, 0) != 0x8a:
                raise InvalidToken
            # Check timestamp
            if ttl is not None:
                timestamp = self._get_timestamp(buffer[1:9])
                current_time = int(time.time())
                if timestamp + ttl < current_time:
                    raise InvalidToken

                if current_time + _MAX_CLOCK_SKEW < timestamp:
                    raise InvalidToken

        buffer = b''
        for data in src:
            buffer += data
            if len(buffer) < 25:
                yield b''
        check_header(buffer)
        # Prepare HMAC checking
        hmac = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
        hmac.update(buffer[0:25])
        # Prepare decryptor
        decryptor = Cipher(
            algorithms.AES(self._encryption_key), modes.CTR(buffer[9:25]),
            self._backend).decryptor()
        # Decrypt ciphertext
        buffer = buffer[25:]
        for data in src:
            if len(data) < 32:
                buffer += data
                yield b''
            hmac.update(buffer)
            yield decryptor.update(buffer)
            buffer = data
        signature = buffer[-32:]
        buffer = buffer[:-32]
        hmac.update(buffer)
        try:
            plaintext = decryptor.update(buffer) + decryptor.finalize()
            yield plaintext
        except ValueError:
            raise InvalidToken
        # Check HMAC
        try:
            hmac.verify(signature)
        except InvalidSignature:
            raise InvalidToken

    @staticmethod
    def _get_timestamp(data: bytes):
        try:
            timestamp, = struct.unpack(">Q", data[1:9])
        except struct.error:
            raise InvalidToken
        return timestamp
