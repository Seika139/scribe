import base64
import binascii
import json
import re
import shutil
from pathlib import Path
from zipfile import ZipFile

import pytest
from cryptography.fernet import Fernet

from scribe.zipper import (
    create_secure_encrypted_zip,
    decrypt_file,
    decrypt_filename,
    encrypt_file,
    encrypt_filename,
    extract_secure_encrypted_zip,
    generate_key_from_password,
)


# パスワードから鍵とソルトが適切な形式で生成されることを検証
def test_generate_key_from_password() -> None:
    password = b"test_password"
    key, salt = generate_key_from_password(password)
    assert isinstance(key, bytes)
    assert isinstance(salt, bytes)
    assert len(key) == 44  # base64 encoded 32 bytes
    assert len(salt) == 16


# 単一ファイルの暗号化→復号で内容が保持されることを確認
def test_encrypt_decrypt_file(tmp_path: Path) -> None:
    password = b"test_password"
    input_file = tmp_path / "test_file.txt"
    input_file.write_text("test data")
    encrypted_file = tmp_path / "test_file.txt.encrypted"
    salt, encrypted_bytes = encrypt_file(input_file, password)
    encrypted_file.write_bytes(encrypted_bytes)
    decrypted_file = tmp_path / "test_file.txt.decrypted"
    decrypt_file(encrypted_file, decrypted_file, password, salt)
    assert Path(decrypted_file).exists()
    assert decrypted_file.read_text() == "test data"


# 単一ファイルをZIP化・復号して元通りになる統合フローをテスト
def test_create_extract_secure_encrypted_zip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Monkeypatch getpass.getpass to avoid interactive password prompt
    monkeypatch.setattr("getpass.getpass", lambda _: "test_password")

    target_file = tmp_path / "test_file.txt"
    target_file.write_text("test data")
    zip_filename = tmp_path / "test_file_encrypted.zip"
    zip_filename = create_secure_encrypted_zip(target_file, zip_filename)
    assert Path(zip_filename).exists()

    extract_dir = tmp_path / "extracted"
    extract_secure_encrypted_zip(zip_filename, extract_dir)
    extracted_file = extract_dir / "test_file.txt"
    assert Path(extracted_file).exists()
    assert extracted_file.read_text() == "test data"


# ディレクトリ丸ごとをZIP化・復号した際に内容が保持されることをテスト
def test_create_extract_secure_encrypted_zip_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Monkeypatch getpass.getpass to avoid interactive password prompt
    monkeypatch.setattr("getpass.getpass", lambda _: "test_password")

    target_dir = tmp_path / "test_dir"
    target_dir.mkdir()
    test_file = target_dir / "test_file.txt"
    test_file.write_text("test data")
    zip_filename = tmp_path / "test_dir_encrypted.zip"
    zip_filename = create_secure_encrypted_zip(target_dir, zip_filename)
    assert Path(zip_filename).exists()

    extract_dir = tmp_path / "extracted"
    extract_secure_encrypted_zip(zip_filename, extract_dir)
    extracted_file = extract_dir / "test_file.txt"
    assert Path(extracted_file).exists()
    assert extracted_file.read_text() == "test data"


def test_extract_secure_encrypted_zip_wrong_password(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """誤ったパスワードでの解凍テスト"""
    # 事前に作成されたパスワード付きZIPファイルを用意
    monkeypatch.setattr("getpass.getpass", lambda _: "correct_password")
    target_file = tmp_path / "secret.txt"
    target_file.write_text("top secret")
    zip_path = create_secure_encrypted_zip(
        target_file, tmp_path / "secret_encrypted.zip"
    )

    try:
        # 間違ったパスワードで解凍を試みる
        monkeypatch.setattr("getpass.getpass", lambda _: "wrong_password")
        extract_dir = tmp_path / "extracted_wrong"
        extract_dir.mkdir(exist_ok=True)

        # ValueError(パスワードが間違っています)が発生することを期待
        with pytest.raises(ValueError, match="エラー: パスワードが間違っています。"):
            extract_secure_encrypted_zip(zip_path, extract_dir)

        # 解凍が失敗しているため、ファイルが存在しないことを確認
        assert not (extract_dir / "secret.txt").exists()

    finally:
        # テスト終了後にファイルを削除
        if zip_path.exists():
            zip_path.unlink()
        if extract_dir.exists():
            shutil.rmtree(extract_dir)


# ZIP名自動生成ロジック(省略時)の挙動を確認
def test_create_secure_encrypted_zip_automatic_filename(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("getpass.getpass", lambda _: "test_password")
    target_file = tmp_path / "data.txt"
    target_file.write_text("some data")
    zip_filename = create_secure_encrypted_zip(target_file)
    assert zip_filename.name == "data_encrypted.zip"
    assert Path(zip_filename).exists()
    zip_filename.unlink()


# 存在しないパス指定時に FileNotFoundError を返すことを確認
def test_create_secure_encrypted_zip_invalid_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """無効なターゲットを指定した場合のテスト"""
    monkeypatch.setattr("getpass.getpass", lambda _: "test_password")
    invalid_target = tmp_path / "non_existent_file"

    try:
        # 存在しないファイルを圧縮しようとする
        with pytest.raises(FileNotFoundError):
            create_secure_encrypted_zip(invalid_target)
    finally:
        # 生成される可能性のあるファイルを確実に削除
        encrypted_zip = tmp_path / "non_existent_file_encrypted.zip"
        if encrypted_zip.exists():
            encrypted_zip.unlink()


# ZIP内部にソルトと暗号化ファイルが含まれることを検証
def test_secure_encrypted_zip_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("getpass.getpass", lambda _: "test_password")
    target_file = tmp_path / "info.txt"
    target_file.write_text("important information")
    zip_filename = create_secure_encrypted_zip(
        target_file, tmp_path / "info_encrypted.zip"
    )

    with ZipFile(zip_filename, "r") as zf:
        namelist = zf.namelist()
        assert "info.txt.salt" in namelist
        assert "info.txt.encrypted" in namelist


# .gitignore を解釈して除外・許可が正しく働くかを確認
def test_create_encrypted_zip_with_gitignore(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """create_secure_encrypted_zip が .gitignore を適用できることをテスト"""
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
    password = "testpass123"  # noqa: S105 テスト用固定値
    monkeypatch.setattr("getpass.getpass", lambda _: password)

    # 圧縮実行
    zip_output = test_dir.parent / "with_gitignore.zip"
    zip_path = create_secure_encrypted_zip(test_dir, zip_output)
    assert zip_path.exists()

    # 解凍用の一時ディレクトリを作成
    extract_dir = test_dir.parent / "extracted_with_gitignore"
    if extract_dir.exists():
        shutil.rmtree(extract_dir)
    extract_dir.mkdir()

    # 解凍を実行
    extract_secure_encrypted_zip(zip_path, extract_dir)

    # .gitignore で除外されないファイルが存在することを確認
    assert (extract_dir / "main.py").exists()  # *.py は除外されない
    assert (extract_dir / "src" / "code.py").exists()  # サブディレクトリ内の .py も保持

    # .gitignore で除外されるファイルが存在しないことを確認
    assert not (extract_dir / "app.log").exists()  # *.log
    # サブディレクトリ内 *.log
    assert not ((extract_dir / "src" / "debug.log").exists())
    assert not (extract_dir / "temp.txt").exists()  # /temp.*
    assert not (extract_dir / "cache").exists()  # cache/
    assert not (extract_dir / "dist").exists()  # /dist/
    assert not (extract_dir / "src" / "temp.tmp").exists()  # /src/*.tmp

    # 除外されないことを確認
    assert (extract_dir / "temp.py").exists()  # !*.py による除外解除

    if zip_output.exists():
        zip_output.unlink()
    if extract_dir.exists():
        shutil.rmtree(extract_dir)


# .gitignore が無い場合は全ファイルを含めることを確認
def test_create_encrypted_zip_without_gitignore(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """.gitignore が無い場合に全ファイルを圧縮することをテスト"""
    # テストディレクトリとファイルの作成
    test_dir = tmp_path / "project_no_ignore"
    test_dir.mkdir()

    # 様々な種類のファイルを作成(.gitignore なし)
    (test_dir / "main.py").write_text("print('Hello')", encoding="utf-8")
    (test_dir / "app.log").write_text("log content", encoding="utf-8")
    (test_dir / "cache").mkdir()
    (test_dir / "cache" / "data.txt").write_text("cache data", encoding="utf-8")

    # パスワード入力のモック
    password = "testpass123"  # noqa: S105 テスト用固定値
    monkeypatch.setattr("getpass.getpass", lambda _: password)

    # 圧縮実行
    zip_output = test_dir.parent / "without_gitignore.zip"
    try:
        zip_path = create_secure_encrypted_zip(test_dir, zip_output)
        assert zip_path.exists()

        # 解凍用の一時ディレクトリを作成
        extract_dir = test_dir.parent / "extracted_without_gitignore"
        if extract_dir.exists():
            shutil.rmtree(extract_dir)
        extract_dir.mkdir()

        # 解凍を実行
        extract_secure_encrypted_zip(zip_path, extract_dir)

        # 全てのファイルが存在することを確認
        assert (extract_dir / "main.py").exists()
        assert (extract_dir / "app.log").exists()
        assert (extract_dir / "cache" / "data.txt").exists()

    finally:
        # テスト終了後にファイルを削除する
        if zip_output.exists():
            zip_output.unlink()
        if extract_dir.exists():
            shutil.rmtree(extract_dir)


# ファイル名の暗号化・復号が各種文字列で双方向に成立することを確認
def test_filename_encryption_decryption() -> None:
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


# ファイル名暗号化メタデータを含むZIPの作成と復号を総合的に検証
def test_create_extract_secure_encrypted_zip_with_filename_encryption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ファイル名の暗号化を含むZIP作成と展開のテスト"""
    # パスワード入力のモック
    monkeypatch.setattr("getpass.getpass", lambda _: "test_password")

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
    assert Path(zip_filename).exists()

    with ZipFile(zip_filename, "r") as zf:
        namelist = zf.namelist()
        # metadata.encryptedの存在を確認
        assert "metadata.encrypted" in namelist
        # すべてのファイルが.encryptedまたは.saltで終わることを確認
        for name in namelist:
            assert name.endswith((".encrypted", ".salt"))

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


# ファイル名を暗号化した場合でも推測不能・復号可能であることを検証
def test_create_extract_secure_encrypted_zip_with_encrypted_filenames(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ファイル名を暗号化してZIP作成と展開するテスト"""
    # パスワード入力のモック
    monkeypatch.setattr("getpass.getpass", lambda _: "test_password")

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

    zip_filename = tmp_path / "encrypted_with_names.zip"
    zip_filename = create_secure_encrypted_zip(
        test_dir, zip_filename, encrypt_filenames=True
    )
    assert Path(zip_filename).exists()

    with ZipFile(zip_filename, "r") as zf:
        namelist = zf.namelist()
        # metadata.encryptedとmetadata.saltの存在を確認
        assert "metadata.encrypted" in namelist
        assert any(name.endswith("metadata.salt") for name in namelist)

        # 暗号化されたファイル名のパターンをチェック
        for name in namelist:
            if name != "metadata.encrypted" and not name.endswith("metadata.salt"):
                # ファイル名がbase64エンコードされたパターンに一致することを確認
                assert name.endswith((".encrypted", ".salt"))
                # 元のファイル名が推測できないことを確認
                name_without_ext = name.replace(".encrypted", "").replace(".salt", "")
                # base64でデコード可能な文字列であることを確認
                try:
                    decoded = base64.urlsafe_b64decode(name_without_ext.encode("ascii"))
                    # デコードされた内容に元のファイル名が含まれていないことを確認
                    assert b"secret_file.txt" not in decoded
                    assert b"classified.txt" not in decoded
                    assert "機密情報.txt".encode() not in decoded
                except (binascii.Error, ValueError):
                    pytest.fail(f"Invalid base64 filename: {name_without_ext}")

                # 暗号化されたファイル名に元のファイル名が含まれていないことを確認
                assert "secret_file.txt" not in name
                assert "classified.txt" not in name
                assert "機密情報.txt" not in name

    # 展開テスト
    extract_dir = tmp_path / "extracted_with_encrypted_names"
    if extract_dir.exists():
        shutil.rmtree(extract_dir)
    extract_dir.mkdir()
    extract_secure_encrypted_zip(zip_filename, extract_dir)

    # オリジナルのファイル名で正しく復元されていることを確認
    assert (extract_dir / "secret_file.txt").exists()
    assert (extract_dir / "private" / "classified.txt").exists()
    assert (extract_dir / "機密情報.txt").exists()

    # ファイルの内容を確認
    assert (extract_dir / "secret_file.txt").read_text() == "confidential data"
    assert (extract_dir / "private" / "classified.txt").read_text() == "top secret data"
    assert (extract_dir / "機密情報.txt").read_text() == "秘密のデータ"

    if zip_filename.exists():
        zip_filename.unlink()
    if extract_dir.exists():
        shutil.rmtree(extract_dir)


# 暗号化後のファイル名が漏洩しない・復号で戻ることを検証
def test_filename_encryption_security() -> None:
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
        except (binascii.Error, ValueError):
            pytest.fail(f"Invalid base64 filename: {encrypted_name}")

        # 復号化で元の名前に戻ることを確認
        decrypted_name = decrypt_filename(encrypted_name, fernet)
        assert decrypted_name == original_name


# 暗号化ZIPでない場合にエラーを出し、何も展開しないことを確認
def test_extract_non_encrypted_zip(tmp_path: Path) -> None:
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
    with pytest.raises(ValueError, match="は暗号化ZIPファイルではありません"):
        extract_secure_encrypted_zip(normal_zip, extract_dir)

    # ディレクトリが空のままであることを確認
    assert not any(extract_dir.iterdir())


# 既存ファイルがあるディレクトリへ展開しても上書きせず共存することを確認
def test_extract_with_existing_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """既存のファイルがある解凍先に対する動作テスト"""
    # パスワード入力のモック
    monkeypatch.setattr("getpass.getpass", lambda _: "test_password")

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


# 相対パス指定の出力ファイルが期待場所に作成されることを確認
def test_zip_with_relative_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """相対パスでのZIPファイル名指定のテスト"""
    # パスワード入力のモック
    monkeypatch.setattr("getpass.getpass", lambda _: "test_password")

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


# .git ディレクトリが除外されることを検証
def test_create_encrypted_zip_excludes_git_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Check that .git directory is excluded from the zip file."""
    monkeypatch.setattr("getpass.getpass", lambda _: "test_password")

    test_dir = tmp_path / "repo_with_git"
    test_dir.mkdir()
    (test_dir / "file.txt").write_text("content")

    # Create .git directory and file
    git_dir = test_dir / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text("git config")

    # サブディレクトリの .git も除外されることを確認
    sub_dir = test_dir / "subdir"
    sub_dir.mkdir()
    (sub_dir / ".git").mkdir()
    (sub_dir / ".git" / "HEAD").write_text("ref: refs/heads/main")

    zip_output = tmp_path / "repo.zip"
    create_secure_encrypted_zip(test_dir, zip_output)

    extract_dir = tmp_path / "extracted_repo"
    extract_secure_encrypted_zip(zip_output, extract_dir)

    # Verify .git is not present
    assert (extract_dir / "file.txt").exists()
    assert not (extract_dir / ".git").exists()
    assert not (extract_dir / "subdir" / ".git").exists()


# ネストした .gitignore の優先順位と否定パターンの扱いを確認
def test_create_encrypted_zip_nested_gitignore_precedence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ネストした .gitignore がスコープ通りに効くことを確認する。"""
    monkeypatch.setattr("getpass.getpass", lambda _: "test_password")

    root = tmp_path / "nested_ignore_test"
    root.mkdir()

    # Root .gitignore
    (root / ".gitignore").write_text("*.log\n")
    (root / "root.log").write_text("should be ignored")
    (root / "root.txt").write_text("should be kept")

    # Subdir A: defines local ignore
    dir_a = root / "dir_a"
    dir_a.mkdir()
    (dir_a / ".gitignore").write_text("ignore_me.txt\n")
    (dir_a / "ignore_me.txt").write_text("should be ignored in A")
    (dir_a / "keep_me.txt").write_text("should be kept in A")
    (dir_a / "sub.log").write_text("should be ignored by root rule")

    # Subdir B: 子の ! ルールで親 *.log を上書きするケース
    dir_b = root / "dir_b"
    dir_b.mkdir()
    (dir_b / ".gitignore").write_text("!important.log\n")
    (dir_b / "important.log").write_text("should be kept despite root *.log")
    (dir_b / "other.log").write_text("should still be ignored")

    zip_output = tmp_path / "nested.zip"
    create_secure_encrypted_zip(root, zip_output)

    extract_dir = tmp_path / "extracted_nested"
    extract_secure_encrypted_zip(zip_output, extract_dir)

    # Assertions
    assert (extract_dir / "root.txt").exists()
    assert not (extract_dir / "root.log").exists()

    assert (extract_dir / "dir_a" / "keep_me.txt").exists()
    assert not (extract_dir / "dir_a" / "ignore_me.txt").exists()
    assert not (extract_dir / "dir_a" / "sub.log").exists()

    # Current implementation might not support !
    # overrides from child gitignore completely if not careful,
    # but let's test if it works with our recursive logic.
    # Our logic combines [parent_patterns] + [current_patterns].
    # pathspec usually handles the list in order,
    # later patterns overriding earlier ones.
    # So !important.log in dir_b should override *.log from root.
    assert (extract_dir / "dir_b" / "important.log").exists()
    assert not (extract_dir / "dir_b" / "other.log").exists()


def test_gitignore_negation_and_gitkeep(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """envs/* 除外 + !envs/.gitkeep など、手動確認したパターンを再現して検証"""
    monkeypatch.setattr("getpass.getpass", lambda _: "test_password")

    root = tmp_path / "sample_ignore"
    root.mkdir()

    # ルート .gitignore: envs 以下を除外しつつ .gitkeep を再包含、.cache も除外
    (root / ".gitignore").write_text(
        ".cache\nenvs/*\n!envs/.gitkeep\n", encoding="utf-8"
    )

    # ファイル・ディレクトリを配置
    (root / "sample.py").write_text("print('ok')", encoding="utf-8")
    envs = root / "envs"
    envs.mkdir()
    (envs / ".gitkeep").write_text("", encoding="utf-8")
    (envs / "secret.env").write_text("SECRET=1", encoding="utf-8")  # 除外される想定

    secrets = root / "secrets"
    secrets.mkdir()
    # サブディレクトリ独自の .gitignore: .gitkeep を残して *.txt を除外
    (secrets / ".gitignore").write_text("!.gitkeep\n*.txt\n", encoding="utf-8")
    (secrets / ".gitkeep").write_text("", encoding="utf-8")
    (secrets / "secret.txt").write_text(
        "top secret", encoding="utf-8"
    )  # 除外される想定

    # .cache のファイルとディレクトリも配置
    cache_dir = root / ".cache"
    cache_dir.mkdir()
    (cache_dir / "cache.txt").write_text("cached", encoding="utf-8")
    sub = root / "sub"
    sub.mkdir()
    (sub / ".cache").write_text("cached file", encoding="utf-8")

    zip_path = tmp_path / "sample_ignore.zip"
    create_secure_encrypted_zip(root, zip_path)

    extract_dir = tmp_path / "extracted_sample_ignore"
    extract_secure_encrypted_zip(zip_path, extract_dir)

    # 期待される包含/除外を確認
    assert (extract_dir / "sample.py").exists()
    assert (extract_dir / "envs" / ".gitkeep").exists()
    assert not (extract_dir / "envs" / "secret.env").exists()
    assert (extract_dir / "secrets" / ".gitkeep").exists()
    assert not (extract_dir / "secrets" / "secret.txt").exists()
    assert not (extract_dir / ".cache").exists()
    assert not (extract_dir / "sub" / ".cache").exists()


def test_gitignore_cache_excludes_directory_and_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """.gitignore の '.cache' エントリがファイル/ディレクトリ双方を除外することを検証"""
    monkeypatch.setattr("getpass.getpass", lambda _: "test_password")

    root = tmp_path / "cache_test"
    root.mkdir()
    (root / ".gitignore").write_text(".cache\n", encoding="utf-8")

    (root / "keep.txt").write_text("keep", encoding="utf-8")

    cache_dir = root / ".cache"
    cache_dir.mkdir()
    (cache_dir / "data.txt").write_text("cache dir content", encoding="utf-8")

    sub = root / "sub"
    sub.mkdir()
    (sub / ".cache").write_text("cache file", encoding="utf-8")

    zip_path = tmp_path / "cache_test.zip"
    create_secure_encrypted_zip(root, zip_path)

    extract_dir = tmp_path / "extracted_cache_test"
    extract_secure_encrypted_zip(zip_path, extract_dir)

    # .cache ディレクトリと .cache ファイルが展開されていないことを確認
    assert (extract_dir / "keep.txt").exists()
    assert not (extract_dir / ".cache").exists()
    assert not (extract_dir / "sub" / ".cache").exists()


def test_password_mismatch_does_not_create_zip(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """圧縮時にパスワードが一致しない場合は ValueError とZIP未生成を確認"""
    responses = iter(["first_pass", "second_pass"])
    monkeypatch.setattr("getpass.getpass", lambda _: next(responses))

    target = tmp_path / "file.txt"
    target.write_text("data", encoding="utf-8")

    zip_path = tmp_path / "file_encrypted.zip"
    with pytest.raises(ValueError, match="パスワードが一致しません"):
        create_secure_encrypted_zip(target, zip_path)
    assert not zip_path.exists()


def test_extract_corrupt_metadata(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """metadata.encrypted を破損させたZIPがパスワードエラーとして扱われ、残骸が出ない"""
    monkeypatch.setattr("getpass.getpass", lambda _: "test_password")
    src = tmp_path / "src.txt"
    src.write_text("secret", encoding="utf-8")
    zip_path = tmp_path / "corrupt_meta.zip"
    create_secure_encrypted_zip(src, zip_path)

    # metadata.encrypted を破損(重複エントリを作らないよう再構築)
    rebuilt = tmp_path / "corrupt_meta_rebuilt.zip"
    with ZipFile(zip_path, "r") as src_zip, ZipFile(rebuilt, "w") as dst_zip:
        for info in src_zip.infolist():
            if info.filename == "metadata.encrypted":
                continue
            dst_zip.writestr(info, src_zip.read(info.filename))
        dst_zip.writestr("metadata.encrypted", b"corrupted")
    rebuilt.replace(zip_path)

    extract_dir = tmp_path / "extract_corrupt_meta"
    with pytest.raises(ValueError, match="パスワードが間違っています"):
        extract_secure_encrypted_zip(zip_path, extract_dir)
    assert not extract_dir.exists()


def test_extract_missing_metadata_salt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """metadata.salt 欠損時に適切なエラーとクリーンアップが行われることを確認"""
    monkeypatch.setattr("getpass.getpass", lambda _: "test_password")
    src = tmp_path / "src.txt"
    src.write_text("secret", encoding="utf-8")
    zip_path = tmp_path / "missing_salt.zip"
    create_secure_encrypted_zip(src, zip_path)

    # metadata.salt を除外したZIPを再構築
    rebuilt = tmp_path / "missing_salt_rebuilt.zip"
    with ZipFile(zip_path, "r") as src_zip, ZipFile(rebuilt, "w") as dst_zip:
        for info in src_zip.infolist():
            if info.filename.endswith("metadata.salt"):
                continue
            dst_zip.writestr(info, src_zip.read(info.filename))
    rebuilt.rename(zip_path)

    extract_dir = tmp_path / "extract_missing_salt"
    with pytest.raises(ValueError, match=r"metadata.saltが見つかりません"):
        extract_secure_encrypted_zip(zip_path, extract_dir)
    assert not extract_dir.exists()


def test_extract_corrupt_file_salt_triggers_cleanup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """1ファイルの .salt を破損させた場合に解凍が失敗し、展開物が残らないことを確認"""
    monkeypatch.setattr("getpass.getpass", lambda _: "test_password")
    root = tmp_path / "multi"
    root.mkdir()
    (root / "a.txt").write_text("A", encoding="utf-8")
    (root / "b.txt").write_text("B", encoding="utf-8")
    zip_path = tmp_path / "multi.zip"
    create_secure_encrypted_zip(root, zip_path)

    rebuilt = tmp_path / "multi_rebuilt.zip"
    with ZipFile(zip_path, "r") as src_zip, ZipFile(rebuilt, "w") as dst_zip:
        salt_name = next(n for n in src_zip.namelist() if n.endswith("b.txt.salt"))
        for info in src_zip.infolist():
            if info.filename == salt_name:
                continue
            dst_zip.writestr(info, src_zip.read(info.filename))
        dst_zip.writestr(salt_name, b"bad_salt")
    rebuilt.replace(zip_path)

    extract_dir = tmp_path / "extract_multi"
    with pytest.raises(ValueError, match="パスワードが間違っています"):
        extract_secure_encrypted_zip(zip_path, extract_dir)
    assert not extract_dir.exists()


def test_extract_handles_windows_style_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Metadata の file_mapping にバックスラッシュ区切りが含まれても正しく展開できる"""
    monkeypatch.setattr("getpass.getpass", lambda _: "test_password")
    root = tmp_path / "paths"
    root.mkdir()
    (root / "dir" / "sub").mkdir(parents=True)
    (root / "dir" / "sub" / "file.txt").write_text("data", encoding="utf-8")
    zip_path = tmp_path / "paths.zip"
    create_secure_encrypted_zip(root, zip_path)

    # metadata を書き換えて file_mapping のキーをバックスラッシュにする
    password = b"test_password"
    with ZipFile(zip_path, "r") as zf:
        metadata_salt_name = next(
            n for n in zf.namelist() if n.endswith("metadata.salt")
        )
        metadata_salt = zf.read(metadata_salt_name)
        encrypted_metadata = zf.read("metadata.encrypted")

    key, _ = generate_key_from_password(password, metadata_salt)
    fernet = Fernet(key)
    metadata = json.loads(fernet.decrypt(encrypted_metadata).decode("utf-8"))
    metadata["file_mapping"] = {
        k.replace("/", "\\"): v for k, v in metadata["file_mapping"].items()
    }
    new_encrypted_metadata = fernet.encrypt(
        json.dumps(metadata, ensure_ascii=False).encode("utf-8")
    )

    rebuilt = tmp_path / "paths_rebuilt.zip"
    with ZipFile(zip_path, "r") as src_zip, ZipFile(rebuilt, "w") as dst_zip:
        for info in src_zip.infolist():
            if info.filename == "metadata.encrypted":
                continue
            dst_zip.writestr(info, src_zip.read(info.filename))
        dst_zip.writestr("metadata.encrypted", new_encrypted_metadata)
    rebuilt.replace(zip_path)

    extract_dir = tmp_path / "extract_paths"
    extract_secure_encrypted_zip(zip_path, extract_dir)
    assert (extract_dir / "dir" / "sub" / "file.txt").exists()
    assert (extract_dir / "dir" / "sub" / "file.txt").read_text() == "data"


def test_gitignore_ignores_empty_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """.gitignore により中身が全除外のディレクトリがZIPに含まれないことを確認"""
    monkeypatch.setattr("getpass.getpass", lambda _: "test_password")
    root = tmp_path / "empty_ignore"
    root.mkdir()
    ignored = root / "ignored_dir"
    ignored.mkdir()
    (ignored / ".gitignore").write_text("*\n", encoding="utf-8")

    zip_path = tmp_path / "empty_ignore.zip"
    create_secure_encrypted_zip(root, zip_path)

    extract_dir = tmp_path / "extract_empty_ignore"
    extract_secure_encrypted_zip(zip_path, extract_dir)

    # ignored_dir は展開されない(ファイルもない)
    assert not (extract_dir / "ignored_dir").exists()


def test_auto_zip_filename_collision(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """既存 *_encrypted.zip がある場合に連番で衝突回避することを確認"""
    monkeypatch.setattr("getpass.getpass", lambda _: "test_password")
    target = tmp_path / "collision.txt"
    target.write_text("x", encoding="utf-8")

    first = create_secure_encrypted_zip(target)
    second = create_secure_encrypted_zip(target)

    assert first.name == "collision_encrypted.zip"
    assert second.name == "collision_encrypted_1.zip"


def test_gitignore_case_sensitive(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """.gitignore が Linux 想定で大文字小文字を区別することを確認"""
    monkeypatch.setattr("getpass.getpass", lambda _: "test_password")
    root = tmp_path / "case"
    root.mkdir()
    (root / ".gitignore").write_text("*.log\n", encoding="utf-8")
    (root / "app.log").write_text("lower", encoding="utf-8")
    (root / "APP.LOG").write_text("upper", encoding="utf-8")

    zip_path = tmp_path / "case.zip"
    create_secure_encrypted_zip(root, zip_path)
    extract_dir = tmp_path / "extract_case"
    extract_secure_encrypted_zip(zip_path, extract_dir)

    assert not (extract_dir / "app.log").exists()
    assert (extract_dir / "APP.LOG").exists()


def test_wrong_password_does_not_remove_existing_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """誤パスワードで既存の解凍先が消えないことを確認"""
    monkeypatch.setattr("getpass.getpass", lambda _: "correct")
    src = tmp_path / "keep.txt"
    src.write_text("keep", encoding="utf-8")
    zip_path = tmp_path / "keep.zip"
    create_secure_encrypted_zip(src, zip_path)

    # 既存ディレクトリとファイルを用意
    extract_dir = tmp_path / "existing_extract"
    extract_dir.mkdir()
    existing_file = extract_dir / "existing.txt"
    existing_file.write_text("existing", encoding="utf-8")

    # 誤パスワードで解凍を試みる
    monkeypatch.setattr("getpass.getpass", lambda _: "wrong")
    with pytest.raises(ValueError, match="パスワードが間違っています"):
        extract_secure_encrypted_zip(zip_path, extract_dir)

    # 既存資産が残っていることを確認
    assert extract_dir.exists()
    assert existing_file.exists()
    assert existing_file.read_text() == "existing"
