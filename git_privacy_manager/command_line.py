import argparse
import getpass
import git_privacy_manager
import os


def impl_decrypt(gpm):
    gpm.decrypt()


def impl_encrypt(gpm):
    gpm.encrypt()


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


def main():
    args = parse_args()
    pswd = getpass.getpass(prompt='Password: ')

    # Apply command
    args.function(git_privacy_manager.GPM(args.path, pswd))
