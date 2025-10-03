#!/usr/bin/env python3
"""
flash_encrypt.py

Encrypt or decrypt files in a directory (e.g. mounted flash drive).
- Streams data (low memory).
- Uses AES-GCM per-file with PBKDF2-derived key from passphrase.
- Default max size = 32GB (can be overridden).

Usage examples:
  # Encrypt all files under /media/usb (recursive), don't delete originals:
  python flash_encrypt.py encrypt /media/usb --recursive

  # Encrypt and delete originals (BE CAREFUL):
  python flash_encrypt.py encrypt /media/usb --recursive --delete-originals

  # Decrypt (will remove .enc extension automatically):
  python flash_encrypt.py decrypt /media/usb --recursive
"""

import argparse
import getpass
import os
import struct
import sys
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

MAGIC = b'ENCFILE1'  # 8 bytes
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
HEADER_FMT = f'{len(MAGIC)}s{SALT_LEN}s{NONCE_LEN}s'  # for struct packing
CHUNK_SIZE = 64 * 1024  # 64 KiB

DEFAULT_MAX_BYTES = 32 * 1024 * 1024 * 1024  # 32 GB
PBKDF2_ITERS = 200_000
KEY_LEN = 32  # AES-256


def derive_key(passphrase: str, salt: bytes) -> bytes:
    return PBKDF2(passphrase.encode('utf-8'), salt, dkLen=KEY_LEN, count=PBKDF2_ITERS, hmac_hash_module=None)


def encrypt_file(src_path: Path, dest_path: Path, passphrase: str):
    salt = get_random_bytes(SALT_LEN)
    nonce = get_random_bytes(NONCE_LEN)
    key = derive_key(passphrase, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    with src_path.open('rb') as fin, dest_path.open('wb') as fout:
        # write header: MAGIC | salt | nonce
        fout.write(MAGIC)
        fout.write(salt)
        fout.write(nonce)

        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            ct = cipher.encrypt(chunk)
            fout.write(ct)

        tag = cipher.digest()
        fout.write(tag)

    # return True if encrypted file exists and is non-empty
    return dest_path.exists() and dest_path.stat().st_size > (len(MAGIC) + SALT_LEN + NONCE_LEN + TAG_LEN)


def decrypt_file(src_path: Path, dest_path: Path, passphrase: str):
    total_size = src_path.stat().st_size
    header_len = len(MAGIC) + SALT_LEN + NONCE_LEN

    if total_size < header_len + TAG_LEN + 1:
        raise ValueError("File too small or not a valid encrypted file")

    with src_path.open('rb') as fin:
        header = fin.read(header_len)
        magic = header[: len(MAGIC)]
        if magic != MAGIC:
            raise ValueError("Magic header mismatch — file not encrypted by this tool (or corrupted).")

        salt = header[len(MAGIC): len(MAGIC) + SALT_LEN]
        nonce = header[len(MAGIC) + SALT_LEN: header_len]
        key = derive_key(passphrase, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        # compute how many bytes are ciphertext (excluding header and tag)
        ct_len = total_size - header_len - TAG_LEN
        bytes_read = 0

        with dest_path.open('wb') as fout:
            while bytes_read < ct_len:
                to_read = min(CHUNK_SIZE, ct_len - bytes_read)
                chunk = fin.read(to_read)
                if not chunk:
                    break
                pt = cipher.decrypt(chunk)
                fout.write(pt)
                bytes_read += len(chunk)

            # read tag from end
            tag = fin.read(TAG_LEN)
            try:
                cipher.verify(tag)
            except ValueError:
                # delete partial output
                fout.close()
                try:
                    dest_path.unlink()
                except Exception:
                    pass
                raise ValueError("Authentication failed: wrong passphrase or file corrupted.")


def process_path(root: Path, passphrase: str, mode: str, recursive: bool, delete_originals: bool, max_bytes: int):
    # gather files
    if root.is_file():
        target_files = [root]
    else:
        if recursive:
            target_files = [p for p in root.rglob('*') if p.is_file()]
        else:
            target_files = [p for p in root.iterdir() if p.is_file()]

    # optionally enforce size limit
    total_size = sum(p.stat().st_size for p in target_files)
    if total_size > max_bytes:
        print(f"Total size {total_size} bytes exceeds limit {max_bytes} bytes. Aborting.")
        sys.exit(1)

    for src in target_files:
        try:
            if mode == 'encrypt':
                if src.suffix == '.enc':
                    print(f"Skipping already-encrypted file: {src}")
                    continue
                dest = src.with_name(src.name + '.enc')
                print(f"Encrypting {src} -> {dest}")
                ok = encrypt_file(src, dest, passphrase)
                if ok and delete_originals:
                    src.unlink()
            else:  # decrypt
                # only process .enc files to avoid accidental decryption
                if src.suffix != '.enc':
                    print(f"Skipping non-.enc file: {src}")
                    continue
                # drop .enc suffix
                dest_name = src.name[:-4] if len(src.name) > 4 else (src.name + '.dec')
                dest = src.with_name(dest_name)
                print(f"Decrypting {src} -> {dest}")
                decrypt_file(src, dest, passphrase)
                if delete_originals:
                    src.unlink()

        except Exception as e:
            print(f"Error processing {src}: {e}")


def main():
    parser = argparse.ArgumentParser(description="Encrypt/decrypt files under a directory (flash drive).")
    parser.add_argument('mode', choices=['encrypt', 'decrypt'], help='encrypt or decrypt')
    parser.add_argument('path', help='path to file or directory (e.g. mount point of flash drive)')
    parser.add_argument('--recursive', action='store_true', help='recurse into subdirectories')
    parser.add_argument('--delete-originals', action='store_true', help='delete originals after successful operation (use with caution)')
    parser.add_argument('--max-bytes', type=int, default=DEFAULT_MAX_BYTES, help='max total bytes to process (default 32GB)')
    parser.add_argument('--passphrase', help='passphrase (if omitted, will be prompted)')
    args = parser.parse_args()

    target = Path(args.path)
    if not target.exists():
        print("Path does not exist:", args.path)
        sys.exit(1)

    passphrase = args.passphrase or getpass.getpass("Passphrase: ")
    if not passphrase:
        print("Empty passphrase not allowed.")
        sys.exit(1)

    process_path(target, passphrase, args.mode, args.recursive, args.delete_originals, args.max_bytes)
    print("Done.")


if __name__ == '__main__':
    main()
