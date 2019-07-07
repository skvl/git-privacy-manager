import gnupg
import hashlib
import json
import logging
from pathlib import Path
from typing import Dict, List, Tuple
from uuid import uuid4


DataBase = Dict[str, Dict[str, str]]


class GPM:
    """
    Implements minimal API for encrypt or decrypt files.

    Encrypts arbitrary nested files in working directory with GnuPG.
    Resulting blobs with random names are stored in single output
    directory. The relationship between actual files and blobs is
    stored in database.
    """

    def __init__(self, path: Path, pswd: str, output: Path = None):
        """
        Parameters
        ----------

        path : str
            Path to working directory with files to encrypt
        pswd : str
            Password for symmetric encryption

        Notes
        -----

        The *.gpm* folder will be created to store metadata.
        The *.gpm/data* folder will be created to store encrypted blobs.
        """
        self._gpg = gnupg.GPG()
        self._pswd = pswd

        self._working_dir = path
        self._metadata_dir = self._working_dir / '.gpm'
        self._metafile = self._metadata_dir / 'metafile'
        if not output:
            self._output_dir = self._metadata_dir / 'data'
        else:
            self._output_dir = output
        self._encrypted_metafile = self._output_dir / 'meta.gpg'

        self._metadata_dir.mkdir(exist_ok=True, parents=True)
        self._output_dir.mkdir(exist_ok=True, parents=True)

        self._all_files: List[Path] = []
        self._metadata: DataBase = {}
        self._metadata_dirty = False

    def decrypt(self):
        """
        Decrypt blobs from data directory into working directory.

        Warnings
        --------
        The files from working directory are not removed!

        Raises
        ------
        RuntimeError
            If no metafile encrypted blob found.
        """
        self._read_metadata_blob()

        files_to_decrypt = []
        for relative_file in self._metadata:
            file = self._working_dir / relative_file
            if not file.is_file() or checksum(file) != self._metadata[relative_file]['checksum']:
                file_enc = (self._output_dir /
                            self._metadata[relative_file]['uuid']).with_suffix('.gpg')
                passphrase = self._metadata[relative_file]['passphrase']
                files_to_decrypt.append((file, file_enc, passphrase))

        for file, file_enc, passphrase in files_to_decrypt:
            self._decrypt_file(file_enc, file, passphrase)

        self._remove_remains_in_working_dir()
        self._remove_ramains_in_output_dir()

    def encrypt(self):
        """
        Encrypts files from working directory into data directory.

        Raises
        ------
        RuntimeError
            If fails to generate UUID for a file.
        """
        self._remove_ramains_in_output_dir()

        files_to_encrypt = []
        for file in self._all_files:
            key = self._key(file)
            file_checksum = checksum(file)
            if not self._contains(file):
                files_to_encrypt.append(self._add(file, file_checksum))
            elif self._differ(file, file_checksum):
                files_to_encrypt.append(self._update_checksum(file, file_checksum))
            else:
                logging.info(
                    f'Skip file "{key}" (%s)' % self._metadata[key]['uuid'])

        for file, file_enc, passphrase in files_to_encrypt:
            self._encrypt_file(file, file_enc, passphrase)

        self._write_metadata()
        self._write_metadata_blob()

    def _read_metadata(self):
        # Load metadata if present
        if self._metafile.is_file():
            with open(self._metafile, 'r') as f:
                self._metadata = json.load(f)
                logging.debug(
                    f'Read metadata from {self._metafile}: f{self._metadata}')

    def _write_metadata(self):
        if self._metadata_dirty:
            with open(self._metafile, 'w+') as f:
                json.dump(self._metadata, f)
                logging.debug(
                    f'Write metadata to {self._metafile}: f{self._metadata}')
            self._metadata_dirty = False

    def _read_metadata_blob(self):
        if not self._encrypted_metafile.is_file():
            raise RuntimeError('Malformed output directory: no metafile encrypted blob found.')
        with open(self._encrypted_metafile, 'rb') as fe:
            self._gpg.decrypt_file(
                fe, passphrase=self._pswd, output=str(self._metafile))
            with open(self._metafile, 'r') as f:
                self._metadata = json.load(f)

    def _write_metadata_blob(self):
        with open(self._metafile, 'rb') as f:
            self._gpg.encrypt_file(
                f, None, symmetric=True, passphrase=self._pswd, output=str(self._encrypted_metafile))

    def _remove_ramains_in_output_dir(self):
        self._all_files = get_all_files(
            self._working_dir, [self._metadata_dir])
        self._read_metadata()
        # Some files have been removed since last commit
        # so remove them
        deleted_files = []

        for relative_file in self._metadata:
            abs_file = self._working_dir / relative_file
            if abs_file not in self._all_files:
                logging.debug(
                    f'Delete file {relative_file}. All files: {self._all_files}. Metadata: {self._metadata}')
                deleted_files.append(relative_file)

        for file in deleted_files:
            logging.info(
                f'File "{file}" have been removed since last commit')
            file_enc = (self._output_dir /
                        self._metadata[file]['uuid']).with_suffix('.gpg')
            if file_enc.is_file():
                file_enc.unlink()
            del self._metadata[file]
            self._metadata_dirty = True

        self._write_metadata()

    def _remove_remains_in_working_dir(self):
        self._all_files = get_all_files(
            self._working_dir, [self._metadata_dir])

        for file in self._all_files:
            key = self._key(file)
            if key not in self._metadata:
                file.unlink()

        self._all_files = get_all_files(
            self._working_dir, [self._metadata_dir])

    def _decrypt_file(self, src: Path, dst: Path, passphrase: str = None):
        if not passphrase:
            passphrase = self._pswd
        dst.parent.mkdir(exist_ok=True)
        with open(src, 'rb') as fe:
            self._gpg.decrypt_file(
                fe, passphrase=passphrase, output=str(dst))

    def _encrypt_file(self, src: Path, dst: Path, passphrase: str = None):
        if not passphrase:
            passphrase = self._pswd
        with open(src, 'rb') as f:
            self._gpg.encrypt_file(
                f, None, symmetric=True, passphrase=passphrase, output=str(dst))

    def _add(self, file: Path, file_checksum: str) -> Tuple[Path, Path, str]:
        """
        Raises
        ------
        RuntimeError
            If fails to generate UUID for a file.
        """
        key = self._key(file)
        file_uuid = self._uuid()
        file_passphrase = file_checksum
        self._metadata[key] = {
            'uuid': file_uuid, 'checksum': file_checksum, 'passphrase': file_passphrase}
        self._metadata_dirty = True
        logging.info(f'Commit new file "{key}" as "{file_uuid}"')

        return file, (self._output_dir / file_uuid).with_suffix('.gpg'), file_passphrase

    def _contains(self, file: Path) -> bool:
        return self._key(file) in self._metadata

    def _differ(self, file: Path, file_checksum: str) -> bool:
        return self._metadata[self._key(file)]['checksum'] != file_checksum

    def _key(self, file: Path) -> str:
        return str(file.relative_to(self._working_dir))

    def _update_checksum(self, file: Path, file_checksum: str) -> Tuple[Path, Path, str]:
        key = self._key(file)
        file_uuid = self._metadata[key]['uuid']
        old_checksum = self._metadata[key]['checksum']
        file_passphrase = file_checksum
        self._metadata[key]['checksum'] = file_checksum
        self._metadata[key]['passphrase'] = file_passphrase
        self._metadata_dirty = True
        logging.info(f'Commit modified file "{key}" as "{file_uuid}": prev checksum="{old_checksum}", new checksum="{file_checksum}"')
        return file, (self._output_dir / file_uuid).with_suffix('.gpg'), file_passphrase

    def _uuid(self) -> str:
        """
        Generate UUID for a file.

        Generated UUID is checked for collision in database.

        Parameters
        ----------
        metadata : dict
            A dictionary with database.

        Raises
        ------
        RuntimeError
            If fails to generate UUID in 10 times.
        """
        for _ in range(10):
            file_uuid = str(uuid4())
            if not self._metadata:
                logging.debug(f'Get UUID: {file_uuid}')
                return file_uuid
            no_collisions = True
            for file_name, file_info in self._metadata.items():
                if file_uuid != file_info['uuid']:
                    continue
                else:
                    logging.debug(
                        f'UUID "{file_uuid}" is used for "{file_name}"')
                    no_collisions = False
                    break
            if no_collisions:
                logging.debug(f'Get UUID: {file_uuid}')
                return file_uuid
        logging.debug('[CRITICAL] Failed to generate UUID')
        raise RuntimeError('Failed to generate UUID')


# TODO Use descriptive sometype instead 'str'
def checksum(file: Path) -> str:
    """
    Calculate the MD5 checksum of a file

    Parameters
    ----------
    file : str
        Path to file.

    Returns
    -------
    str
        MD5 checksum of a file.
    """
    hash_md5 = hashlib.md5()
    with open(file, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def get_all_files(working_dir: Path, exclude: List[Path] = []) -> List[Path]:
    """
    Get list of files in all subfolders in working directory

    The names contain paths relative to working direcotry.

    Returns
    -------
    set
        A list of files in working directory and subdirectories.
    """
    def excluded(entry: Path):
        for path in exclude:
            return path == entry or path in entry.parents

    fs = []
    for entry in working_dir.rglob('*'):
        if entry.is_file() and not excluded(entry):
            fs.append(entry)
    return fs
