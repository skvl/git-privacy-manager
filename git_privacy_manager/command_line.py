import argparse
import click
from getpass import getpass
from git_privacy_manager import GPM
import os
from pathlib import Path
import sys


@click.group()
@click.pass_context
@click.option('--directory', '-d', help='Path to working directory (default: current)', type=click.Path(), default=os.getcwd())
@click.option('--output', '-o', help='Path to output directory', type=click.Path(), default=None)
@click.option('--passphrase', '-p', help='Passphrase for symmetric encryption', type=str, default=None)
def main(ctx, directory, output, passphrase):
    #    args.function(git_privacy_manager.GPM(Path(args.path), pswd, Path(args.output)))
    directory = Path(directory)
    if output:
        output = Path(output)

    gpm = GPM(directory, passphrase, output)

    ctx.obj = {
        'gpm': gpm,
        'passphrase': passphrase,
    }


@main.command()
@click.pass_context
def encrypt(ctx):
    """Encrypt working directory."""
    if not ctx.obj['passphrase']:
        passphrase = getpass(prompt='Enter a passphrase:')
        ctx.obj['gpm'].set_passphrase(passphrase)

    ctx.obj['gpm'].encrypt()


@main.command()
@click.pass_context
def decrypt(ctx):
    """Decrypt working directory."""
    if not ctx.obj['passphrase']:
        passphrase = getpass(prompt='Enter a passphrase:')
        ctx.obj['gpm'].set_passphrase(passphrase)

    ctx.obj['gpm'].decrypt()
