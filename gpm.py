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
        print('[DEBUG] Decrypt new or modified file "%s" from "%s"' % (file, file_enc))
        # Create directory if not exists
        dir_path = os.path.dirname(os.path.abspath(file))
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
        # Decrypt file
        with open(file_enc, 'rb') as fe:
            gpg.decrypt_file(fe, passphrase=pswd, output=file)


def impl_encrypt(path, gpg, pswd):
    meta = {}

    if os.path.exists(metafile):
        with open(metafile, 'r') as f:
            meta = json.load(f)

    files_to_encrypt = []

    for file in get_all_files(path):
        file_md5 = md5(file)
        if file not in meta:
            meta[file] = {'uuid' : str(uuid.uuid4()), 'md5' : file_md5}
            files_to_encrypt.append((file, os.path.join(enc_dir, meta[file]['uuid'] + '.gpg')))
            print('[DEBUG] Commit new file "%s" as "%s"' % (file, meta[file]['uuid']))
        elif meta[file]['md5'] != file_md5:
            print('[DEBUG] Commit modified file "%s" as "%s": prev md5="%s", new md5="%s"' % (file, meta[file]['uuid'], meta[file]['md5'], file_md5))
            meta[file]['md5'] = file_md5
            files_to_encrypt.append((file, os.path.join(enc_dir, meta[file]['uuid'] + '.gpg')))
        else:
            print('[DEBUG] Skip file "%s" (%s)' % (file, meta[file]['uuid']))

    for file, file_enc in files_to_encrypt:
        with open(file, 'rb') as f:
            gpg.encrypt_file(f, None, symmetric=True, passphrase=pswd, output=file_enc)

    if files_to_encrypt:
        with open(metafile, 'w+') as f:
            json.dump(meta, f)
        with open(metafile, 'rb') as f:
            gpg.encrypt_file(f, None, symmetric=True, passphrase=pswd, output=metafile_enc)


def parse_args():
    parser = argparse.ArgumentParser(description='Git Privacy Manager (GPM)')

    parser.add_argument('-p', '--path', dest='path', default=os.getcwd(),
                        help='Path to working directory ("%s" by default)' % os.getcwd())

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