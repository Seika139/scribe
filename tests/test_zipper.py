import os
from pathlib import Path

from pytest import MonkeyPatch

from scribe.zipper import (
    create_secure_encrypted_zip,
    decrypt_file,
    encrypt_file,
    extract_secure_encrypted_zip,
    generate_key_from_password,
)


def test_generate_key_from_password() -> None:
    password = b"test_password"
    key, salt = generate_key_from_password(password)
    assert isinstance(key, bytes)
    assert isinstance(salt, bytes)
    assert len(key) == 44  # base64 encoded 32 bytes
    assert len(salt) == 16


def test_encrypt_decrypt_file(tmp_path: Path) -> None:
    password = b"test_password"
    input_file = tmp_path / "test_file.txt"
    input_file.write_text("test data")
    encrypted_file = tmp_path / "test_file.txt.encrypted"
    salt = encrypt_file(input_file, encrypted_file, password)
    assert os.path.exists(encrypted_file)
    decrypted_file = tmp_path / "test_file.txt.decrypted"
    decrypt_file(encrypted_file, decrypted_file, password, salt)
    assert os.path.exists(decrypted_file)
    assert decrypted_file.read_text() == "test data"


def test_create_extract_secure_encrypted_zip(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    # Monkeypatch getpass.getpass to avoid interactive password prompt
    monkeypatch.setattr("getpass.getpass", lambda x: "test_password")

    target_file = tmp_path / "test_file.txt"
    target_file.write_text("test data")
    zip_filename = tmp_path / "test_file_encrypted.zip"
    zip_filename = create_secure_encrypted_zip(target_file, zip_filename)
    assert os.path.exists(zip_filename)

    extract_dir = tmp_path / "extracted"
    extract_secure_encrypted_zip(zip_filename, extract_dir)
    extracted_file = extract_dir / "test_file.txt"
    assert os.path.exists(extracted_file)
    assert extracted_file.read_text() == "test data"


def test_create_extract_secure_encrypted_zip_directory(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    # Monkeypatch getpass.getpass to avoid interactive password prompt
    monkeypatch.setattr("getpass.getpass", lambda x: "test_password")

    target_dir = tmp_path / "test_dir"
    target_dir.mkdir()
    test_file = target_dir / "test_file.txt"
    test_file.write_text("test data")
    zip_filename = tmp_path / "test_dir_encrypted.zip"
    zip_filename = create_secure_encrypted_zip(target_dir, zip_filename)
    assert os.path.exists(zip_filename)

    extract_dir = tmp_path / "extracted"
    extract_secure_encrypted_zip(zip_filename, extract_dir)
    extracted_file = extract_dir / "test_file.txt"
    assert os.path.exists(extracted_file)
    assert extracted_file.read_text() == "test data"
