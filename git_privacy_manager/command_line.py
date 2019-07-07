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
    if not passphrase:
        passphrase = getpass(prompt='Enter a passphrase:')

    directory = Path(directory)
    if output:
        output = Path(output)

    ctx.obj = {
        'directory': directory,
        'output': output,
        'passphrase': passphrase,
    }


@main.command()
@click.pass_context
def encrypt(ctx):
    GPM(ctx.obj['directory'], ctx.obj['passphrase'], ctx.obj['output']).encrypt()


@main.command()
@click.pass_context
def decrypt(ctx):
    GPM(ctx.obj['directory'], ctx.obj['passphrase'], ctx.obj['output']).decrypt()
