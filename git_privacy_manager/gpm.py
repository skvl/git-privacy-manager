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

    def __init__(self, path: Path, pswd: str):
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
        self.__gpg = gnupg.GPG()
        self.__pswd = pswd

        self.__working_dir = path
        self.__metadata_dir = self.__working_dir / '.gpm'
        self.__metafile = self.__metadata_dir / 'metafile'
        self.__output_dir = self.__metadata_dir / 'data'
        self.__encrypted_metafile = self.__output_dir / 'meta.gpg'

        self.__output_dir.mkdir(exist_ok=True, parents=True)

        self.__all_files: List[Path] = []
        self.__metadata: DataBase = {}
        self.__metadata_dirty = False

    def decrypt(self):
        """
        Decrypt blobs from data directory into working directory.

        Warnings
        --------
        The files from working directory are not removed!
        """
        if not self.__encrypted_metafile.is_file():
            logging.info('No encrypted data')
            return

        self.__read_metadata_blob()

        files_to_decrypt = []
        for relative_file in self.__metadata:
            file = self.__working_dir / relative_file
            if not file.is_file() or checksum(file) != self.__metadata[relative_file]['checksum']:
                file_enc = (self.__output_dir /
                            self.__metadata[relative_file]['uuid']).with_suffix('.gpg')
                files_to_decrypt.append((file, file_enc))

        for file, file_enc in files_to_decrypt:
            self.__decrypt_file(file_enc, file)

        self.__sync_files_with_metadata()

    def encrypt(self):
        """
        Encrypts files from working directory into data directory.
        """
        self.__sync_files_with_metadata()

        files_to_encrypt = []
        for file in self.__all_files:
            key = self.__key(file)
            file_checksum = checksum(file)
            if not self.__contains(file):
                files_to_encrypt.append(self.__add(file, file_checksum=file_checksum))
            elif self.__differ(file, file_checksum):
                files_to_encrypt.append(self.__update_checksum(file, file_checksum))
            else:
                logging.info(
                    f'Skip file "{key}" (%s)' % self.__metadata[key]['uuid'])

        for file, file_enc in files_to_encrypt:
            self.__encrypt_file(file, file_enc)

        self.__write_metadata()
        self.__write_metadata_blob()

    def __read_metadata(self):
        self.__all_files = get_all_files(
            self.__working_dir, [self.__metadata_dir])

        # Load metadata if present
        if self.__metafile.is_file():
            with open(self.__metafile, 'r') as f:
                self.__metadata = json.load(f)
                logging.debug(
                    f'Read metadata from {self.__metafile}: f{self.__metadata}')

    def __write_metadata(self):
        if self.__metadata_dirty:
            with open(self.__metafile, 'w+') as f:
                json.dump(self.__metadata, f)
                logging.debug(
                    f'Write metadata to {self.__metafile}: f{self.__metadata}')
            self.__metadata_dirty = False

    def __read_metadata_blob(self):
        with open(self.__encrypted_metafile, 'rb') as fe:
            self.__gpg.decrypt_file(
                fe, passphrase=self.__pswd, output=str(self.__metafile))
            with open(self.__metafile, 'r') as f:
                self.__metadata = json.load(f)

    def __write_metadata_blob(self):
        with open(self.__metafile, 'rb') as f:
            self.__gpg.encrypt_file(
                f, None, symmetric=True, passphrase=self.__pswd, output=str(self.__encrypted_metafile))

    def __sync_files_with_metadata(self):
        self.__read_metadata()
        # Some files have been removed since last commit
        # so remove them
        deleted_files = []

        for relative_file in self.__metadata:
            abs_file = self.__working_dir / relative_file
            if abs_file not in self.__all_files:
                logging.debug(
                    f'Delete file {relative_file}. All files: {self.__all_files}. Metadata: {self.__metadata}')
                deleted_files.append(relative_file)

        for file in deleted_files:
            logging.info(
                f'File "{file}" have been removed since last commit')
            file_enc = (self.__output_dir /
                        self.__metadata[file]['uuid']).with_suffix('.gpg')
            if file_enc.is_file():
                file_enc.unlink()
            del self.__metadata[file]
            self.__metadata_dirty = True

        self.__write_metadata()

    def __decrypt_file(self, src: Path, dst: Path):
        logging.info(
            f'Decrypt new or modified file "{dst}" from "{src}"')
        dst.parent.mkdir(exist_ok=True)
        with open(src, 'rb') as fe:
            self.__gpg.decrypt_file(
                fe, passphrase=self.__pswd, output=str(dst))

    def __encrypt_file(self, src: Path, dst: Path):
        with open(src, 'rb') as f:
            self.__gpg.encrypt_file(
                f, None, symmetric=True, passphrase=self.__pswd, output=str(dst))

    def __add(self, file: Path, file_checksum: str = None) -> Tuple[Path, Path]:
        key = self.__key(file)
        file_uuid = uuid(self.__metadata)
        if not file_checksum:
            file_checksum = checksum(file)
        self.__metadata[key] = {
            'uuid': file_uuid, 'checksum': file_checksum}
        self.__metadata_dirty = True
        logging.info(
            f'Commit new file "{key}" as "%s"' % self.__metadata[key]['uuid'])

        return file, (self.__output_dir / self.__metadata[key]['uuid']).with_suffix('.gpg')

    def __contains(self, file: Path) -> bool:
        return self.__key(file) in self.__metadata

    def __differ(self, file: Path, file_checksum: str) -> bool:
        return self.__metadata[self.__key(file)]['checksum'] != file_checksum

    def __key(self, file: Path) -> str:
        return str(file.relative_to(self.__working_dir))

    def __update_checksum(self, file: Path, file_checksum: str) -> Tuple[Path, Path]:
        key = self.__key(file)
        self.__metadata[key]['checksum'] = file_checksum
        self.__metadata_dirty = True
        logging.info(f'Commit modified file "{key}" as "%s": prev checksum="%s", new checksum="{file_checksum}"' % (
            self.__metadata[key]['uuid'], self.__metadata[key]['checksum']))
        return file, (self.__output_dir / self.__metadata[key]['uuid']).with_suffix('.gpg')


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


def uuid(metadata: DataBase) -> str:
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
        if not metadata:
            logging.debug(f'Get UUID: {file_uuid}')
            return file_uuid
        no_collisions = True
        for file_name, file_info in metadata.items():
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
