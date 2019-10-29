# TODO Push to cryptography project (https://github.com/pyca/cryptography/)

import base64
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
import os
from pathlib import Path
import struct
import time
from typing import Iterator


class InvalidToken(Exception):
    pass


_MAX_CLOCK_SKEW = 60


class Crypto(object):
    """
    Stream version of Fernet.

    The enrypted stream looks like:
      magic + timestamp + nonce + ciphertext + HMAC signature
    """

    magic = b'\x8a'

    def __init__(self, key: bytes):
        backend = default_backend()

        key = base64.urlsafe_b64decode(key)
        if len(key) != 32:
            raise ValueError(
                'Key must be 32 url-safe base64-encoded bytes.'
            )

        self._signing_key = key[:16]
        self._encryption_key = key[16:]
        self._backend = backend

    @classmethod
    def generate_key(cls) -> bytes:
        return base64.urlsafe_b64encode(os.urandom(32))

    def encrypt_file(self, src: Path, dst: Path):
        with open(src, 'rb') as s, open(dst, 'wb') as d:
            ciphertext = self.encrypt_stream(iter(lambda: s.read(4096), b''))
            for data in ciphertext:
                if data:
                    d.write(data)

    def encrypt_stream(self, src: Iterator[bytes]) -> Iterator[bytes]:
        nonce = os.urandom(16)
        encryptor = Cipher(
            algorithms.AES(self._encryption_key), modes.CTR(
                nonce), self._backend
        ).encryptor()
        hmac = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
        # Format header
        current_time = int(time.time())
        basic_parts = (
            self.magic + struct.pack('>Q', current_time) + nonce
        )
        hmac.update(basic_parts) # The header is part of signature
        yield basic_parts
        # Encryption phase
        for data in src:
            ciphertext = encryptor.update(data)
            hmac.update(ciphertext)
            yield ciphertext
        # Process last bytes if any
        fin = encryptor.finalize()
        hmac.update(fin)
        yield fin
        # Write HMAC
        yield hmac.finalize()

    def decrypt_file(self, src: Path, dst: Path, ttl: int = None):
        with open(src, 'rb') as s, open(dst, 'wb') as d:
            plaintext = self.decrypt_stream(
                iter(lambda: s.read(4096), b''), ttl)
            for data in plaintext:
                if data:
                    d.write(data)

    def decrypt_stream(self, src: Iterator[bytes], ttl: int = None) -> Iterator[bytes]:
        # Use internal buffer as cache. This is needed because iterator could
        # return too small chunks of data.
        buffer = b''
        # Collect enougth bytes for header
        for data in src:
            buffer += data
            if len(buffer) < 25:
                yield b''
        self._check_header(buffer, ttl)
        # Prepare HMAC checking
        hmac = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
        # Prepare decryptor
        decryptor = Cipher(
            algorithms.AES(self._encryption_key), modes.CTR(buffer[9:25]),
            self._backend).decryptor()
        # Decryption phase
        hmac.update(buffer[0:25])  # Header is under HMAC too
        buffer = buffer[25:]      # Drop header. Leave body and HMAC.
        # In cycle process previous block of data if current is large enougth
        # to store HMAC. Otherwise append current block of data to buffer and
        # wait for enother block of ciphertext.
        for data in src:
            if len(data) < 32:
                buffer += data
                yield b''
            hmac.update(buffer)
            yield decryptor.update(buffer)
            buffer = data
        # At this point last 32 bytes should countain HMAC
        signature = buffer[-32:]
        # And signature is not part of HMAC check
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
    def _get_timestamp(data: bytes) -> int:
        try:
            timestamp, = struct.unpack('>Q', data[1:9])
        except struct.error:
            raise InvalidToken
        return timestamp

    @classmethod
    def _check_header(cls, buffer: bytes, ttl: int = None):
        if len(buffer) < 9:
            raise InvalidToken
        # Check magic number
        if buffer[0:1] != cls.magic:
            raise InvalidToken
        # Check timestamp
        if ttl is not None:
            timestamp = cls._get_timestamp(buffer[1:9])
            current_time = int(time.time())
            if timestamp + ttl < current_time:
                raise InvalidToken

            if current_time + _MAX_CLOCK_SKEW < timestamp:
                raise InvalidToken
