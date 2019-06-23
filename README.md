# Git Privacy Manager: GPM

GPM lets you to store sensitive information in open repositories like GitHub.

## Futures

* Encrypts files with GPG
* Stores meta-data to avoid encrypting or decrypting unchanged files
* Stores encrypted blobs in subdirectory
* Follows [Semantic Versioning 2.0.0](https://semver.org/)

## Dependencies

* [GnuPG](https://gnupg.org/)

## Building

```python
python3 setup.py sdist bdist_wheel
```

## Installing

```bash
pip install dist/git_privacy_manager-0.0.1-py3-none-any.whl
```

## Usage

### Encrypt current directory

```bash
gpm encrypt
```

### Decrypt current directory

```bash
gpm decrypt
```
