import gnupg
import hashlib
import json
import logging
from pathlib import Path
from typing import Dict, Set
import uuid


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
        self.gpg = gnupg.GPG()
        self.pswd = pswd

        self.working_dir = path
        self.gpm_dir = self.working_dir / '.gpm'
        self.metafile = self.gpm_dir / 'metafile'
        self.enc_dir = self.gpm_dir / 'data'
        self.metafile_enc = self.enc_dir / 'meta.gpg'

        self.enc_dir.mkdir(exist_ok=True, parents=True)

    def _md5(self, file: Path) -> str:
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

    def _get_all_files(self) -> Set[Path]:
        """
        Get list of files in all subfolders in working directory

        The names contain paths relative to working direcotry.

        Returns
        -------
        set
            A list of files in working directory and subdirectories.
        """
        fs = set()
        for entry in self.working_dir.rglob('*'):
            if entry.is_file() and str(self.gpm_dir) not in str(entry):
                fs.add(entry)
        return fs

    def _uuid(self, metadata: DataBase) -> str:
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
            file_uuid = str(uuid.uuid4())
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

    def decrypt(self):
        """
        Decrypt blobs from data directory into working directory.

        Warnings
        --------
        The files from working directory are not removed!
        """
        if not self.metafile_enc.is_file():
            logging.info('No encrypted data')
            return

        meta = {}
        with open(self.metafile_enc, 'rb') as fe:
            self.gpg.decrypt_file(
                fe, passphrase=self.pswd, output=str(self.metafile))
            with open(self.metafile, 'r') as f:
                meta = json.load(f)

        files_to_decrypt = []
        for relative_file in meta:
            file = self.working_dir / relative_file
            if not file.is_file() or self._md5(file) != meta[relative_file]['hash']:
                file_enc = (self.enc_dir /
                            meta[relative_file]['uuid']).with_suffix('.gpg')
                files_to_decrypt.append((file, file_enc))

        for file, file_enc in files_to_decrypt:
            logging.info(
                f'Decrypt new or modified file "{file}" from "{file_enc}"')
            # Create directory if not exists
            file.parent.mkdir(exist_ok=True)
            # Decrypt file
            with open(file_enc, 'rb') as fe:
                self.gpg.decrypt_file(
                    fe, passphrase=self.pswd, output=str(file))

    def encrypt(self):
        """
        Encrypts files from working directory into data directory.
        """
        all_files = self._get_all_files()

        metadata_changed = False
        meta = {}
        # Load metadata if present
        if self.metafile.is_file():
            with open(self.metafile, 'r') as f:
                meta = json.load(f)
                logging.debug(
                    f'Read metadata from {self.metafile}: f{meta}')

            # Some files have been removed since last commit
            # so remove them
            deleted_files = set()
            for relative_file in meta:
                abs_file = self.working_dir / relative_file
                if abs_file not in all_files:
                    logging.debug(
                        f'Delete file {relative_file}. All files: {all_files}. Metadata: {meta}')
                    deleted_files.add(relative_file)
            for file in deleted_files:
                logging.info(
                    f'File "{file}" have been removed since last commit')
                file_enc = (self.enc_dir /
                            meta[file]['uuid']).with_suffix('.gpg')
                if file_enc.is_file():
                    file_enc.unlink()
                del meta[file]
                metadata_changed = True

        files_to_encrypt = []

        for abs_file in all_files:
            file = str(abs_file.relative_to(self.working_dir))
            file_md5 = self._md5(abs_file)
            if file not in meta:
                logging.debug(
                    f'Generate UUID for file: {abs_file} . Metadata: {meta}')
                file_uuid = self._uuid(meta)
                meta[file] = {'uuid': file_uuid, 'hash': file_md5}
                metadata_changed = True
                file_enc = str((self.enc_dir /
                                meta[file]['uuid']).with_suffix('.gpg'))
                files_to_encrypt.append((abs_file, file_enc))
                logging.info(
                    f'Commit new file "{file}" as "%s"' % meta[file]['uuid'])
            elif meta[file]['hash'] != file_md5:
                meta[file]['hash'] = file_md5
                metadata_changed = True
                file_enc = str((self.enc_dir /
                                meta[file]['uuid']).with_suffix('.gpg'))
                files_to_encrypt.append((abs_file, file_enc))
                logging.info(f'Commit modified file "{file}" as "%s": prev md5="%s", new md5="{file_md5}"' % (
                    meta[file]['uuid'], meta[file]['hash']))
            else:
                logging.info(
                    f'Skip file "{file}" (%s)' % meta[file]['uuid'])

        for file, file_enc in files_to_encrypt:
            with open(file, 'rb') as f:
                self.gpg.encrypt_file(
                    f, None, symmetric=True, passphrase=self.pswd, output=file_enc)

        if metadata_changed:
            with open(self.metafile, 'w+') as f:
                json.dump(meta, f)
                logging.debug(
                    f'Write metadata to {self.metafile}: f{meta}')
            with open(self.metafile, 'rb') as f:
                self.gpg.encrypt_file(
                    f, None, symmetric=True, passphrase=self.pswd, output=str(self.metafile_enc))
