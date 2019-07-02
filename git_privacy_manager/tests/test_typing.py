"""
Test type hints (see [1]_).

References
----------

.. [1] https://docs.python.org/3/library/typing.html
"""
import unittest
import subprocess


class TestTyping(unittest.TestCase):

    @unittest.skip('Workaround for Travis CI. Remove later.')
    def test_typing(self):
        rc = subprocess.run(['mypy', 'git_privacy_manager'], capture_output=True, text=True)
        self.assertEqual(rc.returncode, 0, f'Type checking failed: stdout="{rc.stdout}" stderr="{rc.stderr}"')
