import argparse
import getpass
import gnupg
import hashlib
import json
import os
import uuid


working_dir = '.gpm'
metafile = os.path.join(working_dir, 'metafile')

enc_dir = os.path.join(working_dir, 'data')
metafile_enc = os.path.join(enc_dir, 'meta.gpg')


def md5(path):
    hash_md5 = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def get_all_files(path):
    fs = set()
    for root, _, files in os.walk(path):
        for file in files:
            rel_dir = os.path.relpath(root, path)
            rel_file = os.path.join(rel_dir, file)
            if working_dir not in rel_file:
                fs.add(rel_file)
    return fs


def impl_decrypt(path, gpg, pswd):
    if not os.path.exists(metafile_enc):
        print('No encrypted data')
        return

    meta = {}
    with open(metafile_enc, 'rb') as fe:
        gpg.decrypt_file(fe, passphrase=pswd, output=metafile)
        with open(metafile, 'r') as f:
            meta = json.load(f)

    files_to_decrypt = []
    for file in meta:
        if not os.path.exists(file) or md5(file) != meta[file]['md5']:
            files_to_decrypt.append((file, os.path.join(enc_dir, meta[file]['uuid'] + '.gpg')))

    for file, file_enc in files_to_decrypt:
        print(f'[DEBUG] Decrypt new or modified file "{file}" from "{file_enc}"')
        # Create directory if not exists
        dir_path = os.path.dirname(os.path.abspath(file))
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
        # Decrypt file
        with open(file_enc, 'rb') as fe:
            gpg.decrypt_file(fe, passphrase=pswd, output=file)


def impl_encrypt(path, gpg, pswd):
    all_files = get_all_files(path)

    metadata_changed = False
    meta = {}
    # Load metadata if present
    if os.path.exists(metafile):
        with open(metafile, 'r') as f:
            meta = json.load(f)

        # Some files have been removed since last commit
        # so remove them
        deleted_files = set()
        for file in meta:
            if file not in all_files:
                deleted_files.add(file)
        for file in deleted_files:
            print(f'[DEBUG] File "{file}" have been removed since last commit')
            file_enc = os.path.join(enc_dir, meta[file]['uuid'] + '.gpg')
            if os.path.exists(file_enc):
                os.remove(file_enc)
            del meta[file]
            metadata_changed = True

    files_to_encrypt = []

    for file in all_files:
        file_md5 = md5(file)
        if file not in meta:
            meta[file] = {'uuid' : str(uuid.uuid4()), 'md5' : file_md5}
            metadata_changed = True
            files_to_encrypt.append((file, os.path.join(enc_dir, meta[file]['uuid'] + '.gpg')))
            print(f'[DEBUG] Commit new file "{file}" as "%s"' % meta[file]['uuid'])
        elif meta[file]['md5'] != file_md5:
            meta[file]['md5'] = file_md5
            metadata_changed = True
            files_to_encrypt.append((file, os.path.join(enc_dir, meta[file]['uuid'] + '.gpg')))
            print(f'[DEBUG] Commit modified file "{file}" as "%s": prev md5="%s", new md5="{file_md5}"' % (meta[file]['uuid'], meta[file]['md5']))
        else:
            print(f'[DEBUG] Skip file "{file}" (%s)' % meta[file]['uuid'])

    for file, file_enc in files_to_encrypt:
        with open(file, 'rb') as f:
            gpg.encrypt_file(f, None, symmetric=True, passphrase=pswd, output=file_enc)

    if metadata_changed:
        with open(metafile, 'w+') as f:
            json.dump(meta, f)
        with open(metafile, 'rb') as f:
            gpg.encrypt_file(f, None, symmetric=True, passphrase=pswd, output=metafile_enc)


def parse_args():
    parser = argparse.ArgumentParser(description='Git Privacy Manager (GPM)')

    parser.add_argument('-p', '--path', dest='path', default=os.getcwd(),
                        help=f'Path to working directory ("{os.getcwd()}" by default)')

    subparsers = parser.add_subparsers()

    encrypt = subparsers.add_parser('encrypt', help='Encrypt all files')
    encrypt.set_defaults(function=impl_encrypt)

    decrypt = subparsers.add_parser('decrypt', help='Decrypt all files')
    decrypt.set_defaults(function=impl_decrypt)

    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()

    # Go to working directory
    os.chdir(args.path)

    if not os.path.exists(enc_dir):
        os.makedirs(enc_dir)

    gpg = gnupg.GPG()
    pswd = getpass.getpass(prompt='Password: ')
    
    # Apply command
    args.function(args.path, gpg, pswd)