import gnupg
import hashlib
import json
import logging
from pathlib import Path
from typing import Dict, List, Set
from uuid import uuid4


DataBase = Dict[Path, Dict[str, str]]


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

        meta = {}
        with open(self.__encrypted_metafile, 'rb') as fe:
            self.__gpg.decrypt_file(
                fe, passphrase=self.__pswd, output=str(self.__metafile))
            with open(self.__metafile, 'r') as f:
                meta = json.load(f)

        files_to_decrypt = []
        for relative_file in meta:
            file = self.__working_dir / relative_file
            if not file.is_file() or checksum(file) != meta[relative_file]['checksum']:
                file_enc = (self.__output_dir /
                            meta[relative_file]['uuid']).with_suffix('.gpg')
                files_to_decrypt.append((file, file_enc))

        for file, file_enc in files_to_decrypt:
            logging.info(
                f'Decrypt new or modified file "{file}" from "{file_enc}"')
            # Create directory if not exists
            file.parent.mkdir(exist_ok=True)
            # Decrypt file
            with open(file_enc, 'rb') as fe:
                self.__gpg.decrypt_file(
                    fe, passphrase=self.__pswd, output=str(file))

    def encrypt(self):
        """
        Encrypts files from working directory into data directory.
        """
        all_files = get_all_files(self.__working_dir, [self.__metadata_dir])

        metadata_changed = False
        meta = {}
        # Load metadata if present
        if self.__metafile.is_file():
            with open(self.__metafile, 'r') as f:
                meta = json.load(f)
                logging.debug(
                    f'Read metadata from {self.__metafile}: f{meta}')

            # Some files have been removed since last commit
            # so remove them
            deleted_files = set()
            for relative_file in meta:
                abs_file = self.__working_dir / relative_file
                if abs_file not in all_files:
                    logging.debug(
                        f'Delete file {relative_file}. All files: {all_files}. Metadata: {meta}')
                    deleted_files.add(relative_file)
            for file in deleted_files:
                logging.info(
                    f'File "{file}" have been removed since last commit')
                file_enc = (self.__output_dir /
                            meta[file]['uuid']).with_suffix('.gpg')
                if file_enc.is_file():
                    file_enc.unlink()
                del meta[file]
                metadata_changed = True

        files_to_encrypt = []

        for abs_file in all_files:
            file = str(abs_file.relative_to(self.__working_dir))
            file_checksum = checksum(abs_file)
            if file not in meta:
                logging.debug(
                    f'Generate UUID for file: {abs_file} . Metadata: {meta}')
                file_uuid = uuid(meta)
                meta[file] = {'uuid': file_uuid, 'checksum': file_checksum}
                metadata_changed = True
                file_enc = str((self.__output_dir /
                                meta[file]['uuid']).with_suffix('.gpg'))
                files_to_encrypt.append((abs_file, file_enc))
                logging.info(
                    f'Commit new file "{file}" as "%s"' % meta[file]['uuid'])
            elif meta[file]['checksum'] != file_checksum:
                meta[file]['checksum'] = file_checksum
                metadata_changed = True
                file_enc = str((self.__output_dir /
                                meta[file]['uuid']).with_suffix('.gpg'))
                files_to_encrypt.append((abs_file, file_enc))
                logging.info(f'Commit modified file "{file}" as "%s": prev checksum="%s", new checksum="{file_checksum}"' % (
                    meta[file]['uuid'], meta[file]['checksum']))
            else:
                logging.info(
                    f'Skip file "{file}" (%s)' % meta[file]['uuid'])

        for file, file_enc in files_to_encrypt:
            with open(file, 'rb') as f:
                self.__gpg.encrypt_file(
                    f, None, symmetric=True, passphrase=self.__pswd, output=file_enc)

        if metadata_changed:
            with open(self.__metafile, 'w+') as f:
                json.dump(meta, f)
                logging.debug(
                    f'Write metadata to {self.__metafile}: f{meta}')
            with open(self.__metafile, 'rb') as f:
                self.__gpg.encrypt_file(
                    f, None, symmetric=True, passphrase=self.__pswd, output=str(self.__encrypted_metafile))


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


def get_all_files(working_dir: Path, exclude: List[Path] = []) -> Set[Path]:
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

    fs = set()
    for entry in working_dir.rglob('*'):
        if entry.is_file() and not excluded(entry):
            fs.add(entry)
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
