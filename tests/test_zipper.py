import os
from pathlib import Path
from zipfile import ZipFile

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


# def test_extract_secure_encrypted_zip_wrong_password(
#     tmp_path: Path,
#     monkeypatch: MonkeyPatch,
# ) -> None:
#     # 事前に作成されたパスワード付きZIPファイルを用意
#     monkeypatch.setattr("getpass.getpass", lambda x: "correct_password")
#     target_file = tmp_path / "secret.txt"
#     target_file.write_text("top secret")
#     create_secure_encrypted_zip(target_file, tmp_path / "secret_encrypted.zip")

#     # 間違ったパスワードで解凍を試みる
#     monkeypatch.setattr("getpass.getpass", lambda x: "wrong_password")
#     extract_dir = tmp_path / "extracted_wrong"
#     with raises(
#         Exception,
#         match="復号化に失敗しました: パスワードが間違っている可能性があります。",
#     ):
#         extract_secure_encrypted_zip(target_file, extract_dir)
#     assert not (extract_dir / "secret.txt").exists()


def test_create_secure_encrypted_zip_automatic_filename(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr("getpass.getpass", lambda x: "test_password")
    target_file = tmp_path / "data.txt"
    target_file.write_text("some data")
    zip_filename = create_secure_encrypted_zip(target_file)
    assert zip_filename.name == "data_encrypted.zip"
    assert os.path.exists(zip_filename)
    zip_filename.unlink()


# def test_create_secure_encrypted_zip_invalid_target(
#     tmp_path: Path,
#     monkeypatch: MonkeyPatch,
# ) -> None:
#     """無効なターゲットを指定した場合のテスト"""
#     monkeypatch.setattr("getpass.getpass", lambda x: "test_password")
#     invalid_target = tmp_path / "non_existent_file"
#     with raises(SystemExit):
#         create_secure_encrypted_zip(invalid_target)
#     Path(tmp_path / "non_existent_file_encrypted.zip").unlink()


def test_secure_encrypted_zip_content(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr("getpass.getpass", lambda x: "test_password")
    target_file = tmp_path / "info.txt"
    target_file.write_text("important information")
    zip_filename = create_secure_encrypted_zip(
        target_file, tmp_path / "info_encrypted.zip"
    )

    with ZipFile(zip_filename, "r") as zf:
        namelist = zf.namelist()
        assert "info.txt.salt" in namelist
        assert "info.txt.encrypted" in namelist


def test_create_encrypted_zip_with_gitignore(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """create_secure_encrypted_zip が .gitignore のルールを正しく適用できることをテスト"""
    # テストディレクトリとファイルの作成
    test_dir = tmp_path / "project"
    test_dir.mkdir()

    # テスト用の .gitignore ファイルを作成
    gitignore_content = """
*.log
cache/
/dist/
/temp.*
/src/*.tmp
!*.py
"""
    (test_dir / ".gitignore").write_text(gitignore_content, encoding="utf-8")

    # テスト用のファイルを作成
    (test_dir / "main.py").write_text("print('Hello')", encoding="utf-8")
    (test_dir / "app.log").write_text("log content", encoding="utf-8")
    (test_dir / "temp.txt").write_text("temporary", encoding="utf-8")
    (test_dir / "temp.py").write_text("temporary py", encoding="utf-8")
    (test_dir / "cache").mkdir()
    (test_dir / "cache" / "data.txt").write_text("cache data", encoding="utf-8")
    (test_dir / "dist").mkdir()
    (test_dir / "dist" / "app.exe").write_text("binary", encoding="utf-8")
    (test_dir / "src").mkdir()
    (test_dir / "src" / "code.py").write_text("source code", encoding="utf-8")
    (test_dir / "src" / "temp.tmp").write_text("temporary", encoding="utf-8")
    (test_dir / "src" / "debug.log").write_text("debug info", encoding="utf-8")

    # パスワード入力のモック
    password = "testpass123"
    monkeypatch.setattr("getpass.getpass", lambda _: password)

    # 圧縮実行
    zip_output = test_dir.parent / "with_gitignore.zip"
    try:
        zip_path = create_secure_encrypted_zip(test_dir, zip_output)
        assert zip_path.exists()

        # 解凍用の一時ディレクトリを作成
        extract_dir = test_dir.parent / "extracted_with_gitignore"
        extract_dir.mkdir()

        # 解凍を実行
        extract_secure_encrypted_zip(zip_path, extract_dir)

        # .gitignore で除外されないファイルが存在することを確認
        assert (extract_dir / "main.py").exists()  # *.py は除外されない
        assert (
            extract_dir / "src" / "code.py"
        ).exists()  # サブディレクトリ内の .py も除外されない

        # .gitignore で除外されるファイルが存在しないことを確認
        assert not (extract_dir / "app.log").exists()  # *.log
        assert not (
            extract_dir / "src" / "debug.log"
        ).exists()  # サブディレクトリ内の *.log
        assert not (extract_dir / "temp.txt").exists()  # /temp.*
        assert not (extract_dir / "cache").exists()  # cache/
        assert not (extract_dir / "dist").exists()  # /dist/
        assert not (extract_dir / "src" / "temp.tmp").exists()  # /src/*.tmp

        # 除外されないことを確認
        assert (extract_dir / "temp.py").exists()  # !*.py による除外解除

    finally:
        # テスト終了後にファイルを削除
        if zip_output.exists():
            zip_output.unlink()
        if extract_dir.exists():
            import shutil

            shutil.rmtree(extract_dir)


def test_create_encrypted_zip_without_gitignore(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    """create_secure_encrypted_zip が .gitignore が存在しない場合、全ファイルを圧縮することをテスト"""
    # テストディレクトリとファイルの作成
    test_dir = tmp_path / "project_no_ignore"
    test_dir.mkdir()

    # 様々な種類のファイルを作成（.gitignore なし）
    (test_dir / "main.py").write_text("print('Hello')", encoding="utf-8")
    (test_dir / "app.log").write_text("log content", encoding="utf-8")
    (test_dir / "cache").mkdir()
    (test_dir / "cache" / "data.txt").write_text("cache data", encoding="utf-8")

    # パスワード入力のモック
    password = "testpass123"
    monkeypatch.setattr("getpass.getpass", lambda _: password)

    # 圧縮実行
    zip_output = test_dir.parent / "without_gitignore.zip"
    try:
        zip_path = create_secure_encrypted_zip(test_dir, zip_output)
        assert zip_path.exists()

        # 解凍用の一時ディレクトリを作成
        extract_dir = test_dir.parent / "extracted_without_gitignore"
        extract_dir.mkdir()

        # 解凍を実行
        extract_secure_encrypted_zip(zip_path, extract_dir)

        # 全てのファイルが存在することを確認
        assert (extract_dir / "main.py").exists()
        assert (extract_dir / "app.log").exists()
        assert (extract_dir / "cache" / "data.txt").exists()

    finally:
        # テスト終了後にファイルを削除
        if zip_output.exists():
            zip_output.unlink()
        if extract_dir.exists():
            import shutil

            shutil.rmtree(extract_dir)
