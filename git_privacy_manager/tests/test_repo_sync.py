"""
Test synchronizing two repositories.
"""

import git_privacy_manager as gpm
import os
from pathlib import Path
import tempfile
import unittest
from .utils import add_file, copy_files, files_in_directory, get_all_files


class TestRepoSync(unittest.TestCase):
    def setUp(self):
        self.gpm1 = gpm.GPM(Path(tempfile.mkdtemp()), '123')
        self.gpm2 = gpm.GPM(Path(tempfile.mkdtemp()), '123')

        # Initial setup
        ## Add file into first repository
        add_file(self.gpm1._working_dir)
        self.gpm1.encrypt()
        self._sync_repo2()

    def test_repo_clone(self):
        self._if_repos_equal()

    def test_repo_sync_new_file(self):
        add_file(self.gpm1._working_dir)
        self.gpm1.encrypt() # Add new file into first repository
        self._sync_repo2()
        self._if_repos_equal()

    def test_repo_sync_delete_file(self):
        f = get_all_files(self.gpm1._working_dir)[0]
        f.unlink()
        self.gpm1.encrypt()  # Remove file from first repository
        self._sync_repo2()
        self._if_repos_equal()

    def _sync_repo2(self):
        ## First remove
        for f in get_all_files(self.gpm2._output_dir):
            f.unlink()
        ## Then copy files from first to second
        ## There is no difference how to do that
        copy_files(self.gpm1._output_dir, self.gpm2._output_dir)
        # Decrypt and check that files matches
        self.gpm2.decrypt()

    def _if_repos_equal(self):
        repo1_files = get_all_files(self.gpm1._working_dir)
        repo2_files = get_all_files(self.gpm2._working_dir)

        self.assertEqual(len(repo1_files), len(repo2_files))

        for f in repo1_files:
            f2 = self.gpm2._working_dir / f.name

            self.assertTrue(f2 in repo2_files)

            # File contents must be equal
            f_data = ''
            with open(f, 'r') as fh:
                f_data = fh.read()

            f2_data = ''
            with open(f2, 'r') as fh:
                f2_data = fh.read()

            self.assertEqual(f_data, f2_data)
