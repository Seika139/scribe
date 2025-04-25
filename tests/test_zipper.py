import base64
import os
import re
from pathlib import Path
from zipfile import ZipFile

from cryptography.fernet import Fernet
from pytest import MonkeyPatch, raises

from scribe.zipper import (
    create_secure_encrypted_zip,
    decrypt_file,
    decrypt_filename,
    encrypt_file,
    encrypt_filename,
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


def test_extract_secure_encrypted_zip_wrong_password(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    """誤ったパスワードでの解凍テスト"""
    # 事前に作成されたパスワード付きZIPファイルを用意
    monkeypatch.setattr("getpass.getpass", lambda x: "correct_password")
    target_file = tmp_path / "secret.txt"
    target_file.write_text("top secret")
    zip_path = create_secure_encrypted_zip(
        target_file, tmp_path / "secret_encrypted.zip"
    )

    try:
        # 間違ったパスワードで解凍を試みる
        monkeypatch.setattr("getpass.getpass", lambda x: "wrong_password")
        extract_dir = tmp_path / "extracted_wrong"
        extract_dir.mkdir(exist_ok=True)

        # ValueError（パスワードが間違っています）が発生することを期待
        with raises(ValueError, match="エラー: パスワードが間違っています。"):
            extract_secure_encrypted_zip(zip_path, extract_dir)

        # 解凍が失敗しているため、ファイルが存在しないことを確認
        assert not (extract_dir / "secret.txt").exists()

    finally:
        # テスト終了後にファイルを削除
        if zip_path.exists():
            zip_path.unlink()
        if extract_dir.exists():
            import shutil

            shutil.rmtree(extract_dir)


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


def test_create_secure_encrypted_zip_invalid_target(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    """無効なターゲットを指定した場合のテスト"""
    monkeypatch.setattr("getpass.getpass", lambda _: "test_password")
    invalid_target = tmp_path / "non_existent_file"

    try:
        # 存在しないファイルを圧縮しようとする
        with raises(FileNotFoundError):
            create_secure_encrypted_zip(invalid_target)
    finally:
        # 生成される可能性のあるファイルを確実に削除
        encrypted_zip = tmp_path / "non_existent_file_encrypted.zip"
        if encrypted_zip.exists():
            encrypted_zip.unlink()


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


def test_filename_encryption_decryption(tmp_path: Path) -> None:
    """ファイル名の暗号化と復号化のテスト"""
    # キーの生成
    password = b"test_password"
    key, _ = generate_key_from_password(password)
    fernet = Fernet(key)

    # 通常のファイル名
    original_name = "test_file.txt"
    encrypted_name = encrypt_filename(original_name, fernet)
    decrypted_name = decrypt_filename(encrypted_name, fernet)
    assert decrypted_name == original_name

    # パスを含むファイル名
    original_name_with_path = "dir1/subdir/test_file.txt"
    encrypted_name_with_path = encrypt_filename(original_name_with_path, fernet)
    decrypted_name_with_path = decrypt_filename(encrypted_name_with_path, fernet)
    assert decrypted_name_with_path == original_name_with_path

    # 日本語ファイル名
    original_name_jp = "テスト_ファイル.txt"
    encrypted_name_jp = encrypt_filename(original_name_jp, fernet)
    decrypted_name_jp = decrypt_filename(encrypted_name_jp, fernet)
    assert decrypted_name_jp == original_name_jp


def test_create_extract_secure_encrypted_zip_with_filename_encryption(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    """ファイル名の暗号化を含むZIP作成と展開のテスト"""
    # パスワード入力のモック
    monkeypatch.setattr("getpass.getpass", lambda x: "test_password")

    # テストディレクトリとファイルの作成
    test_dir = tmp_path / "test_dir"
    test_dir.mkdir()

    # 通常のファイル
    normal_file = test_dir / "test_file.txt"
    normal_file.write_text("test data")

    # サブディレクトリ内のファイル
    sub_dir = test_dir / "subdir"
    sub_dir.mkdir()
    sub_file = sub_dir / "sub_file.txt"
    sub_file.write_text("sub dir data")

    # 日本語名のファイル
    jp_file = test_dir / "テスト.txt"
    jp_file.write_text("日本語テスト")

    # ZIPファイルの作成
    zip_filename = tmp_path / "encrypted.zip"
    zip_filename = create_secure_encrypted_zip(test_dir, zip_filename)
    assert os.path.exists(zip_filename)

    # ZIPファイルの内容確認（暗号化されたファイル名のみ確認）
    with ZipFile(zip_filename, "r") as zf:
        namelist = zf.namelist()
        # metadata.encryptedの存在を確認
        assert "metadata.encrypted" in namelist
        # すべてのファイルが.encryptedまたは.saltで終わることを確認
        for name in namelist:
            if name != "metadata.encrypted":
                assert name.endswith(".encrypted") or name.endswith(".salt")

    # 展開テスト
    extract_dir = tmp_path / "extracted"
    extract_secure_encrypted_zip(zip_filename, extract_dir)

    # オリジナルのファイル名で復元されていることを確認
    assert (extract_dir / "test_file.txt").exists()
    assert (extract_dir / "subdir" / "sub_file.txt").exists()
    assert (extract_dir / "テスト.txt").exists()

    # ファイルの内容を確認
    assert (extract_dir / "test_file.txt").read_text() == "test data"
    assert (extract_dir / "subdir" / "sub_file.txt").read_text() == "sub dir data"
    assert (extract_dir / "テスト.txt").read_text() == "日本語テスト"


def test_create_extract_secure_encrypted_zip_with_encrypted_filenames(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    """ファイル名を暗号化してZIP作成と展開するテスト"""
    # パスワード入力のモック
    monkeypatch.setattr("getpass.getpass", lambda x: "test_password")

    # テストディレクトリとファイルの作成
    test_dir = tmp_path / "test_dir_encrypted_names"
    test_dir.mkdir()

    # 通常のファイル
    normal_file = test_dir / "secret_file.txt"
    normal_file.write_text("confidential data")

    # サブディレクトリ内のファイル
    sub_dir = test_dir / "private"
    sub_dir.mkdir()
    sub_file = sub_dir / "classified.txt"
    sub_file.write_text("top secret data")

    # 日本語名のファイル
    jp_file = test_dir / "機密情報.txt"
    jp_file.write_text("秘密のデータ")

    # ZIPファイルの作成（ファイル名暗号化オプションを有効化）
    zip_filename = tmp_path / "encrypted_with_names.zip"
    zip_filename = create_secure_encrypted_zip(
        test_dir, zip_filename, encrypt_filenames=True
    )
    assert os.path.exists(zip_filename)

    # ZIPファイルの内容を確認（暗号化されたファイル名のパターンを検証）
    with ZipFile(zip_filename, "r") as zf:
        namelist = zf.namelist()
        # metadata.encryptedとmetadata.saltの存在を確認
        assert "metadata.encrypted" in namelist
        assert any(name.endswith("metadata.salt") for name in namelist)

        # 暗号化されたファイル名のパターンをチェック
        for name in namelist:
            if name not in ["metadata.encrypted"] and not name.endswith(
                "metadata.salt"
            ):
                # ファイル名がbase64エンコードされたパターンに一致することを確認
                assert name.endswith(".encrypted") or name.endswith(".salt")
                # 元のファイル名が推測できないことを確認
                name_without_ext = name.replace(".encrypted", "").replace(".salt", "")
                # base64でデコード可能な文字列であることを確認
                try:
                    decoded = base64.urlsafe_b64decode(name_without_ext.encode("ascii"))
                    # デコードされた内容に元のファイル名が含まれていないことを確認
                    assert b"secret_file.txt" not in decoded
                    assert b"classified.txt" not in decoded
                    assert "機密情報.txt".encode("utf-8") not in decoded
                except Exception:
                    assert False, f"Invalid base64 filename: {name_without_ext}"

                # 暗号化されたファイル名に元のファイル名が含まれていないことを確認
                assert "secret_file.txt" not in name
                assert "classified.txt" not in name
                assert "機密情報.txt" not in name

    # 展開テスト
    extract_dir = tmp_path / "extracted_with_encrypted_names"
    extract_secure_encrypted_zip(zip_filename, extract_dir)

    # オリジナルのファイル名で正しく復元されていることを確認
    assert (extract_dir / "secret_file.txt").exists()
    assert (extract_dir / "private" / "classified.txt").exists()
    assert (extract_dir / "機密情報.txt").exists()

    # ファイルの内容を確認
    assert (extract_dir / "secret_file.txt").read_text() == "confidential data"
    assert (extract_dir / "private" / "classified.txt").read_text() == "top secret data"
    assert (extract_dir / "機密情報.txt").read_text() == "秘密のデータ"


def test_filename_encryption_security(tmp_path: Path) -> None:
    """ファイル名の暗号化セキュリティテスト"""
    # キーの生成
    password = b"test_password"
    key, _ = generate_key_from_password(password)
    fernet = Fernet(key)

    # テストするファイル名
    sensitive_names = [
        "password.txt",
        "credit_card_info.csv",
        "secret_key.pem",
        "機密情報.doc",
        "パスワード.txt",
        "private/sensitive_data.json",
    ]

    for original_name in sensitive_names:
        encrypted_name = encrypt_filename(original_name, fernet)

        # 暗号化された名前が元の名前を含まないことを確認
        assert original_name not in encrypted_name
        # スラッシュが暗号化されていることを確認
        if "/" in original_name:
            assert "/" not in encrypted_name
        # 拡張子が暗号化されていることを確認
        if "." in original_name:
            file_ext = original_name.split(".")[-1]
            assert file_ext not in encrypted_name

        # 暗号化された名前がbase64エンコードされた形式であることを確認
        try:
            decoded = base64.urlsafe_b64decode(encrypted_name.encode("ascii"))
            # デコードされた内容に元の名前の一部が含まれていないことを確認
            name_parts = re.split(r"[./]", original_name)
            for part in name_parts:
                if len(part) > 3:  # 短すぎる部分文字列は除外
                    assert part.encode("utf-8") not in decoded
        except Exception:
            assert False, f"Invalid base64 filename: {encrypted_name}"

        # 復号化で元の名前に戻ることを確認
        decrypted_name = decrypt_filename(encrypted_name, fernet)
        assert decrypted_name == original_name


def test_extract_non_encrypted_zip(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    """通常のZIPファイルを解凍しようとした場合のテスト"""
    # 通常のZIPファイルを作成
    test_file = tmp_path / "normal.txt"
    test_file.write_text("normal content")
    normal_zip = tmp_path / "normal.zip"

    with ZipFile(normal_zip, "w") as zf:
        zf.write(test_file, test_file.name)

    extract_dir = tmp_path / "extracted_normal"
    extract_dir.mkdir()

    # 暗号化ZIPでないファイルの解凍を試みる
    with raises(ValueError, match="は暗号化ZIPファイルではありません"):
        extract_secure_encrypted_zip(normal_zip, extract_dir)

    # ディレクトリが空のままであることを確認
    assert not any(extract_dir.iterdir())


def test_extract_with_existing_files(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    """既存のファイルがある解凍先に対する動作テスト"""
    # パスワード入力のモック
    monkeypatch.setattr("getpass.getpass", lambda x: "test_password")

    # 暗号化ZIPファイルの作成
    source_file = tmp_path / "secret.txt"
    source_file.write_text("secret content")
    zip_path = create_secure_encrypted_zip(
        source_file, tmp_path / "secret_encrypted.zip"
    )

    # 解凍先に既存のファイルを作成
    extract_dir = tmp_path / "extract_with_existing"
    extract_dir.mkdir()
    existing_file = extract_dir / "existing.txt"
    existing_file.write_text("existing content")

    # 解凍を実行
    extract_secure_encrypted_zip(zip_path, extract_dir)

    # 既存のファイルが維持されていることを確認
    assert existing_file.exists()
    assert existing_file.read_text() == "existing content"

    # 新しいファイルも正しく解凍されていることを確認
    decrypted_file = extract_dir / "secret.txt"
    assert decrypted_file.exists()
    assert decrypted_file.read_text() == "secret content"


def test_zip_with_relative_path(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    """相対パスでのZIPファイル名指定のテスト"""
    # パスワード入力のモック
    monkeypatch.setattr("getpass.getpass", lambda x: "test_password")

    # サブディレクトリを作成
    sub_dir = tmp_path / "subdir"
    sub_dir.mkdir()
    source_file = sub_dir / "data.txt"
    source_file.write_text("test data")

    # 相対パスでZIPファイル名を指定
    relative_zip = Path("output.zip")  # 相対パス
    zip_path = create_secure_encrypted_zip(source_file, relative_zip)

    # ZIPファイルがsource_fileと同じディレクトリに作成されていることを確認
    assert zip_path.parent == source_file.parent
    assert zip_path.exists()

    # 解凍して内容を確認
    extract_dir = tmp_path / "extracted_relative"
    extract_secure_encrypted_zip(zip_path, extract_dir)
    decrypted_file = extract_dir / "data.txt"
    assert decrypted_file.exists()
    assert decrypted_file.read_text() == "test data"
