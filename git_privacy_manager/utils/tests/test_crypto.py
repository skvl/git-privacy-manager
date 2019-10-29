from ..crypto import Crypto

from filecmp import cmp
import os
from pathlib import Path
from tempfile import TemporaryDirectory, mkstemp
import unittest


def add_file(working_directory, size=1):
    file_data = b'a' * size
    file_handle, file_path = mkstemp(dir=working_directory, text=True)
    with open(file_handle, 'wb') as f:
        f.write(file_data)

    return Path(file_path)


class TestCryptoFile(unittest.TestCase):
    def test_file_8192B(self):
        with TemporaryDirectory() as d:
            original = add_file(d, 8192)
            encrypted = original.with_suffix('.enc')
            unencrypted = original.with_suffix('.unenc')
            c = Crypto(Crypto.generate_key())
            c.encrypt_file(original, encrypted)
            c.decrypt_file(encrypted, unencrypted)
            self.assertTrue(cmp(original, unencrypted))

class TestCryptoStream(unittest.TestCase):
    def _body_stream(self, size : int, block_size : int = 1):
        def plaintext_generator(buffer):
            while buffer:
                yield buffer[:block_size]
                buffer = buffer[block_size:]

        def ciphertext_generator(buffer):
            while buffer:
                yield buffer[:block_size]
                buffer = buffer[block_size:]

        c = Crypto(Crypto.generate_key())

        plaintext = b'a' * size
        encryptor = c.encrypt_stream(plaintext_generator(plaintext))
        encrypted = b''
        for data in encryptor:
            encrypted += data

        decryptor = c.decrypt_stream(ciphertext_generator(encrypted))
        decrypted = b''
        for data in decryptor:
            decrypted += data

        self.assertEqual(plaintext, decrypted)

    def test_stream_1B(self):
        self._body_stream(1)

    def test_stream_16B(self):
        self._body_stream(16)

    def test_stream_4KB(self):
        self._body_stream(4096)

    def test_stream_4KB_128B(self):
        self._body_stream(4096, 128)

    def test_stream_8KB_4KB(self):
        self._body_stream(8192, 4096)
