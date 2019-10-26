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


class TestCrypto(unittest.TestCase):
    def _body(self, size : int):
        with TemporaryDirectory() as d:
            original = add_file(d, size)
            encrypted = original.with_suffix('.enc')
            unencrypted = original.with_suffix('.unenc')
            c = Crypto(Crypto.generate_key())
            c.encrypt(original, encrypted)
            c.decrypt(encrypted, unencrypted)
            self.assertTrue(cmp(original, unencrypted))

    def test_file_1B(self):
        self._body(1)

    def test_file_16B(self):
        self._body(16)

    def test_file_4095B(self):
        self._body(4095)

    def test_file_4096B(self):
        self._body(4096)

    def test_file_4097B(self):
        self._body(4097)

    def test_file_8192B(self):
        self._body(8192)
