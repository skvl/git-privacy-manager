"""
Test Git Privacy Manager against CRUD ([1]_) operations.

References
----------

.. [1] https://en.wikipedia.org/wiki/Create,_read,_update_and_delete
"""
import git_privacy_manager as gpm
import os
import tempfile
import unittest
from unittest.mock import patch
import uuid  # Used to generate random string


def add_file(working_directory):
    file_data = str(uuid.uuid4())
    file_handle, file_path = tempfile.mkstemp(dir=working_directory, text=True)
    with open(file_handle, 'w') as f:
        f.write(file_data)

    return file_path, file_data


class TestSingleFileCRUD(unittest.TestCase):
    """
    Test CRUD operations against single file.
    """

    def setUp(self):
        self.working_directory = tempfile.mkdtemp()
        self.pswd = '123'
        self.gpm = gpm.GPM(self.working_directory, self.pswd)

        self.file_path, self.file_data = add_file(self.working_directory)
        self.gpm.encrypt()

    def tearDown(self):
        pass

    def test_add_single_file(self):
        os.remove(self.file_path)
        self.gpm.decrypt()

        self.assertTrue(os.path.isfile(self.file_path))
        with open(self.file_path, 'r') as f:
            self.assertEqual(self.file_data, f.read())

    def test_update_single_file(self):
        file_data_updated = str(uuid.uuid4())
        with open(self.file_path, 'w') as f:
            f.write(file_data_updated)
        self.gpm.encrypt()
        os.remove(self.file_path)
        self.gpm.decrypt()

        self.assertTrue(os.path.isfile(self.file_path))
        with open(self.file_path, 'r') as f:
            self.assertEqual(file_data_updated, f.read())

    def test_delete_single_file(self):
        os.remove(self.file_path)
        self.gpm.encrypt()
        self.gpm.decrypt()

        self.assertFalse(os.path.exists(self.file_path))


class TestMultipleFilesCRUD(unittest.TestCase):
    """
    Test CRUD operations against a pair of files.
    """

    def setUp(self):
        self.working_directory = tempfile.mkdtemp()
        self.pswd = '123'
        self.gpm = gpm.GPM(self.working_directory, self.pswd)

        self.file_1_path, self.file_1_data = add_file(self.working_directory)
        self.file_2_path, self.file_2_data = add_file(self.working_directory)
        self.gpm.encrypt()

    def tearDown(self):
        pass

    def test_add_multiple_files(self):
        os.remove(self.file_1_path)
        os.remove(self.file_2_path)
        self.gpm.decrypt()

        self.assertTrue(os.path.isfile(self.file_1_path))
        with open(self.file_1_path, 'r') as f:
            self.assertEqual(self.file_1_data, f.read())

        self.assertTrue(os.path.isfile(self.file_2_path))
        with open(self.file_2_path, 'r') as f:
            self.assertEqual(self.file_2_data, f.read())

    def test_update_one_of_many_files(self):
        file_data_updated = str(uuid.uuid4())
        with open(self.file_1_path, 'w') as f:
            f.write(file_data_updated)
        self.gpm.encrypt()
        os.remove(self.file_1_path)
        os.remove(self.file_2_path)
        self.gpm.decrypt()

        self.assertTrue(os.path.isfile(self.file_1_path))
        with open(self.file_1_path, 'r') as f:
            self.assertEqual(file_data_updated, f.read())

        self.assertTrue(os.path.isfile(self.file_2_path))
        with open(self.file_2_path, 'r') as f:
            self.assertEqual(self.file_2_data, f.read())

    def test_update_many_files(self):
        file_1_data_updated = str(uuid.uuid4())
        with open(self.file_1_path, 'w') as f:
            f.write(file_1_data_updated)
        file_2_data_updated = str(uuid.uuid4())
        with open(self.file_2_path, 'w') as f:
            f.write(file_2_data_updated)
        self.gpm.encrypt()
        os.remove(self.file_1_path)
        os.remove(self.file_2_path)
        self.gpm.decrypt()

        self.assertTrue(os.path.isfile(self.file_1_path))
        with open(self.file_1_path, 'r') as f:
            self.assertEqual(file_1_data_updated, f.read())

        self.assertTrue(os.path.isfile(self.file_2_path))
        with open(self.file_2_path, 'r') as f:
            self.assertEqual(file_2_data_updated, f.read())

    def test_delete_one_of_many_files(self):
        os.remove(self.file_1_path)
        self.gpm.encrypt()
        self.gpm.decrypt()

        self.assertFalse(os.path.exists(self.file_1_path))

        self.assertTrue(os.path.isfile(self.file_2_path))
        with open(self.file_2_path, 'r') as f:
            self.assertEqual(self.file_2_data, f.read())

    @patch('git_privacy_manager.gpm.uuid')
    def test_uuid_collision_raises(self, mock_uuid):
        mock_uuid.uuid4.return_value = 1
        add_file(self.working_directory)
        add_file(self.working_directory)
        with self.assertRaises(RuntimeError):
            self.gpm.encrypt()

    @patch('git_privacy_manager.gpm.uuid')
    def test_uuid_collision_success(self, mock_uuid):
        mock_uuid.uuid4.side_effect = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2]
        add_file(self.working_directory)
        add_file(self.working_directory)
        self.gpm.encrypt()
