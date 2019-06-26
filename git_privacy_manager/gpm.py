import gnupg
import hashlib
import json
import logging
import os
import uuid


class GPM:
    def __init__(self, path, pswd):
        self.gpg = gnupg.GPG()
        self.pswd = pswd

        self.working_dir = path
        self.gpm_dir = '.gpm'
        self.metafile = os.path.join(self.gpm_dir, 'metafile')
        self.enc_dir = os.path.join(self.gpm_dir, 'data')
        self.metafile_enc = os.path.join(self.enc_dir, 'meta.gpg')

        os.chdir(self.working_dir)
        if not os.path.exists(self.enc_dir):
            os.makedirs(self.enc_dir)

    def _md5(self, file):
        hash_md5 = hashlib.md5()
        with open(file, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    def _get_all_files(self):
        fs = set()
        for root, _, files in os.walk(self.working_dir):
            for file in files:
                rel_dir = os.path.relpath(root, self.working_dir)
                rel_file = os.path.join(rel_dir, file)
                if self.gpm_dir not in rel_file:
                    fs.add(rel_file)
        return fs

    def _uuid(self, metadata):
        for _ in range(10):
            file_uuid = str(uuid.uuid4())
            if not metadata:
                return file_uuid
            no_collisions = True
            for file_name, file_info in metadata.items():
                if file_uuid not in file_info.values():
                    continue
                else:
                    logging.info(
                        f'[DEBUG] UUID "{file_uuid}" is used for "{file_name}"')
                    no_collisions = False
                    break
            if no_collisions:
                return file_uuid
        raise RuntimeError('Failed to generate UUID')

    def decrypt(self):
        if not os.path.exists(self.metafile_enc):
            logging.info('No encrypted data')
            return

        meta = {}
        with open(self.metafile_enc, 'rb') as fe:
            self.gpg.decrypt_file(
                fe, passphrase=self.pswd, output=self.metafile)
            with open(self.metafile, 'r') as f:
                meta = json.load(f)

        files_to_decrypt = []
        for file in meta:
            if not os.path.exists(file) or self._md5(file) != meta[file]['md5']:
                files_to_decrypt.append(
                    (file, os.path.join(self.enc_dir, meta[file]['uuid'] + '.gpg')))

        for file, file_enc in files_to_decrypt:
            logging.info(
                f'[DEBUG] Decrypt new or modified file "{file}" from "{file_enc}"')
            # Create directory if not exists
            dir_path = os.path.dirname(os.path.abspath(file))
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
            # Decrypt file
            with open(file_enc, 'rb') as fe:
                self.gpg.decrypt_file(fe, passphrase=self.pswd, output=file)

    def encrypt(self):
        all_files = self._get_all_files()

        metadata_changed = False
        meta = {}
        # Load metadata if present
        if os.path.exists(self.metafile):
            with open(self.metafile, 'r') as f:
                meta = json.load(f)

            # Some files have been removed since last commit
            # so remove them
            deleted_files = set()
            for file in meta:
                if file not in all_files:
                    deleted_files.add(file)
            for file in deleted_files:
                logging.info(
                    f'[DEBUG] File "{file}" have been removed since last commit')
                file_enc = os.path.join(
                    self.enc_dir, meta[file]['uuid'] + '.gpg')
                if os.path.exists(file_enc):
                    os.remove(file_enc)
                del meta[file]
                metadata_changed = True

        files_to_encrypt = []

        for file in all_files:
            file_md5 = self._md5(file)
            if file not in meta:
                file_uuid = self._uuid(meta)
                meta[file] = {'uuid': file_uuid, 'md5': file_md5}
                metadata_changed = True
                files_to_encrypt.append(
                    (file, os.path.join(self.enc_dir, meta[file]['uuid'] + '.gpg')))
                logging.info(
                    f'[DEBUG] Commit new file "{file}" as "%s"' % meta[file]['uuid'])
            elif meta[file]['md5'] != file_md5:
                meta[file]['md5'] = file_md5
                metadata_changed = True
                files_to_encrypt.append(
                    (file, os.path.join(self.enc_dir, meta[file]['uuid'] + '.gpg')))
                logging.info(f'[DEBUG] Commit modified file "{file}" as "%s": prev md5="%s", new md5="{file_md5}"' % (
                    meta[file]['uuid'], meta[file]['md5']))
            else:
                logging.info(
                    f'[DEBUG] Skip file "{file}" (%s)' % meta[file]['uuid'])

        for file, file_enc in files_to_encrypt:
            with open(file, 'rb') as f:
                self.gpg.encrypt_file(
                    f, None, symmetric=True, passphrase=self.pswd, output=file_enc)

        if metadata_changed:
            with open(self.metafile, 'w+') as f:
                json.dump(meta, f)
            with open(self.metafile, 'rb') as f:
                self.gpg.encrypt_file(
                    f, None, symmetric=True, passphrase=self.pswd, output=self.metafile_enc)
