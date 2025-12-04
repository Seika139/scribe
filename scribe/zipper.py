import base64
import getpass
import json
import os
import sys
import zipfile
from pathlib import Path

import pathspec
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pathspec.patterns.gitwildmatch import GitWildMatchPattern


def generate_key_from_password(
    password: bytes,
    salt: bytes | None = None,
) -> tuple[bytes, bytes]:
    """
    パスワードとソルトから暗号化キーを生成します。

    Args:
        password: パスワードのバイト列
        salt: ソルトのバイト列（省略可能）

    Returns:
        生成されたキーとソルトのタプル
    """
    if salt is None:
        salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )

    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key, salt


def encrypt_file(input_path: Path, password: bytes) -> tuple[bytes, bytes]:
    """ファイルを暗号化し、暗号化済みデータとソルトを返します。"""
    salt = os.urandom(16)
    key, _ = generate_key_from_password(password, salt)
    f = Fernet(key)
    with open(input_path, "rb") as input_file:
        data = input_file.read()
    encrypted_data = f.encrypt(data)
    return salt, encrypted_data


def decrypt_file(
    input_path: Path,
    output_path: Path,
    password: bytes,
    salt: bytes,
) -> None:
    """暗号化されたファイルを復号化します。"""
    key, _ = generate_key_from_password(password, salt)
    f = Fernet(key)
    with open(input_path, "rb") as input_file:
        encrypted_data = input_file.read()
    decrypted_data = f.decrypt(encrypted_data)
    with open(output_path, "wb") as outfile:
        outfile.write(decrypted_data)


def load_gitignore(directory: Path) -> pathspec.PathSpec | None:
    """
    指定されたディレクトリの .gitignore ファイルを読み込み、
    pathspec.PathSpec オブジェクトを返します。
    .gitignore が存在しない場合は None を返します。
    """
    gitignore_path = directory / ".gitignore"
    if not gitignore_path.is_file():
        return None

    with open(gitignore_path, encoding="utf-8") as f:
        gitignore = pathspec.PathSpec.from_lines(GitWildMatchPattern, f.readlines())
    return gitignore


def should_ignore_file(
    path: Path, base_dir: Path, gitignore: pathspec.PathSpec | None
) -> bool:
    """
    指定されたファイルが .gitignore のパターンに一致するかどうかを判定します。
    """
    if gitignore is None:
        return False

    # ファイルパスをbase_dirからの相対パスに変換
    # Windowsでも常にPOSIX形式のパス（フォワードスラッシュ）を使用
    relative_path = path.relative_to(base_dir).as_posix()
    return gitignore.match_file(relative_path)


def encrypt_filename(filename: str, fernet: Fernet) -> str:
    """
    ファイル名を暗号化します。

    Args:
        filename: 暗号化するファイル名
        fernet: 暗号化に使用するFernetオブジェクト

    Returns:
        暗号化されたファイル名（Fernetトークン）
    """
    try:
        print(f"暗号化前のファイル名: {filename}")
        encrypted_bytes = fernet.encrypt(filename.encode("utf-8"))
        encrypted_name = encrypted_bytes.decode("ascii")
        print(f"暗号化後のファイル名: {encrypted_name}")
        return encrypted_name
    except Exception as e:
        raise ValueError(
            f"ファイル名の暗号化に失敗しました: {filename} ({str(e)})"
        ) from e


def decrypt_filename(encrypted_filename: str, fernet: Fernet) -> str:
    """
    暗号化されたファイル名を復号化します。

    Args:
        encrypted_filename: 暗号化されたファイル名（Fernetトークン）
        fernet: 復号化に使用するFernetオブジェクト

    Returns:
        復号化されたファイル名
    """
    try:
        print(f"復号化前のファイル名: {encrypted_filename}")
        decrypted_bytes = fernet.decrypt(encrypted_filename.encode("ascii"))
        decrypted_name = decrypted_bytes.decode("utf-8")
        print(f"復号化後のファイル名: {decrypted_name}")
        return decrypted_name
    except Exception as e:
        raise ValueError(
            f"ファイル名の復号化に失敗しました: {encrypted_filename} ({str(e)})"
        ) from e


def create_secure_encrypted_zip(
    target: Path, zip_filename: Path | None = None, encrypt_filenames: bool = False
) -> Path:
    """
    指定されたファイルまたはディレクトリを、cryptographyライブラリで暗号化した上でZIPファイルとして作成します。
    ファイル名とディレクトリ名も暗号化することができます。
    出力ZIPファイル名を省略された場合は自動で命名し、既存ファイル名との重複を避けます。
    .gitignore ファイルが存在する場合は、そのルールに従ってファイルを除外します。

    Args:
        target: 圧縮対象のファイルまたはディレクトリのパス
        zip_filename: 出力するZIPファイルのパス（省略可能）
        encrypt_filenames: ファイル名を暗号化するかどうか（デフォルトはFalse）

    Returns:
        作成されたZIPファイルのパス

    Raises:
        FileNotFoundError: 指定されたパスが存在しない場合
        ValueError: パスワードが一致しない場合、またはパスの種類が不正な場合
        OSError: ファイルの読み書きに失敗した場合
    """
    if not target.exists():
        raise FileNotFoundError(f"指定されたパス '{target}' が見つかりません。")

    password_bytes = getpass.getpass("圧縮パスワードを入力してください: ").encode(
        "utf-8"
    )
    password_confirm_bytes = getpass.getpass(
        "圧縮パスワードを再入力してください: "
    ).encode("utf-8")

    if password_bytes != password_confirm_bytes:
        raise ValueError("エラー: パスワードが一致しません。")

    # パスの正規化
    target = target.resolve()

    # メタデータ用のソルトを生成
    metadata_salt = os.urandom(16)
    metadata_key, _ = generate_key_from_password(password_bytes, metadata_salt)
    metadata_fernet = Fernet(metadata_key)

    # 共通のソルトを生成（ファイルの暗号化に使用）
    common_salt = os.urandom(16)

    if zip_filename is None:
        if target.is_file():
            zip_filename_base = target.stem + "_encrypted"
            zip_filename_dir = target.parent
        else:
            zip_filename_base = target.name + "_encrypted"
            zip_filename_dir = target.parent
        zip_filename_suffix = ".zip"
        zip_filename = zip_filename_dir / f"{zip_filename_base}{zip_filename_suffix}"
        counter = 1
        while zip_filename.exists():
            zip_filename = (
                zip_filename_dir / f"{zip_filename_base}_{counter}{zip_filename_suffix}"
            )
            counter += 1
    else:
        # zip_filenameが絶対パスでない場合は、target.parentからの相対パスとして解決
        if not zip_filename.is_absolute():
            zip_filename = target.parent / zip_filename
        zip_filename = zip_filename.resolve()

    try:
        file_mapping: dict[str, str] = (
            {}
        )  # キー: 元のファイル名, 値: 暗号化されたファイル名

        with zipfile.ZipFile(
            zip_filename, "w", zipfile.ZIP_DEFLATED, compresslevel=9
        ) as zf:
            if target.is_file():
                original_name = target.name
                if encrypt_filenames:
                    encrypted_name = encrypt_filename(original_name, metadata_fernet)
                else:
                    encrypted_name = original_name

                # file_mappingのキーを元のファイル名に変更
                file_mapping[original_name] = encrypted_name

                salt, encrypted_bytes = encrypt_file(target, password_bytes)
                zf.writestr(f"{encrypted_name}.salt", salt)
                zf.writestr(f"{encrypted_name}.encrypted", encrypted_bytes)
                print(
                    f"ファイル '{target}' を '{zip_filename}' にパスワード付きで暗号化・圧縮しました。"
                )
            elif target.is_dir():
                # .gitignore の読み込み
                gitignore = load_gitignore(target)
                if gitignore:
                    print(
                        f".gitignore ファイルを読み込みました: {target / '.gitignore'}"
                    )

                for root, _, files in os.walk(target):
                    root_path = Path(root)
                    for file in files:
                        file_path = root_path / file
                        # .gitignore と一致するファイルはスキップ
                        if should_ignore_file(file_path, target, gitignore):
                            print(
                                f"除外: {file_path.relative_to(target)} (.gitignore に一致)"
                            )
                            continue

                        # OSに依存しない形式でパスを扱うよう修正
                        relative_path = file_path.relative_to(target).as_posix()
                        if encrypt_filenames:
                            encrypted_name = encrypt_filename(
                                relative_path, metadata_fernet
                            )
                        else:
                            encrypted_name = relative_path

                        # file_mappingのキーを元のファイル名に変更
                        file_mapping[relative_path] = encrypted_name

                        salt, encrypted_bytes = encrypt_file(file_path, password_bytes)
                        zf.writestr(f"{encrypted_name}.salt", salt)
                        zf.writestr(f"{encrypted_name}.encrypted", encrypted_bytes)

                print(
                    f"ディレクトリ '{target}' を '{zip_filename}' にパスワード付きで暗号化・圧縮しました。"
                )
            else:
                raise ValueError(
                    f"指定されたパス '{target}' はファイルまたはディレクトリではありません。"
                )

            # メタデータを暗号化して保存
            metadata = {
                "file_mapping": file_mapping,
                "common_salt": base64.b64encode(common_salt).decode("ascii"),
                "encrypt_filenames": encrypt_filenames,
            }
            metadata_json = json.dumps(metadata, ensure_ascii=False)
            encrypted_metadata = metadata_fernet.encrypt(metadata_json.encode("utf-8"))
            zf.writestr("metadata.encrypted", encrypted_metadata)
            zf.writestr("metadata.salt", metadata_salt)

        return zip_filename

    except Exception:
        # エラー発生時は作成途中のZIPファイルを削除
        if zip_filename and zip_filename.exists():
            zip_filename.unlink()
        raise


def extract_secure_encrypted_zip(
    zip_filepath: Path, extract_dir: Path | None = None
) -> None:
    """
    cryptographyライブラリで暗号化されたZIPファイルを指定したディレクトリに解凍し、復号化します。
    ファイル名とディレクトリ名も復号化されます。
    解凍先ディレクトリが省略された場合は、ZIPファイルと同じ場所に作成します。

    Args:
        zip_filepath: 解凍するZIPファイルのパス
        extract_dir: 解凍先ディレクトリのパス（省略可能）

    Raises:
        FileNotFoundError: ZIPファイルが見つからない場合
        zipfile.BadZipFile: 無効なZIPファイルの場合
        ValueError: パスワードが間違っている場合、またはファイルが暗号化ZIPではない場合
        OSError: ファイルの読み書きに失敗した場合
    """
    # 先にZIPファイルを検証
    if not zip_filepath.exists():
        raise FileNotFoundError(
            f"指定されたファイル '{zip_filepath}' が見つかりません。"
        )

    try:
        with zipfile.ZipFile(zip_filepath, "r") as zf:
            # 暗号化ZIPファイルの必須要素を確認
            if "metadata.encrypted" not in zf.namelist():
                raise ValueError(
                    f"エラー: '{zip_filepath}' は暗号化ZIPファイルではありません。"
                    "このプログラムで作成された暗号化ZIPファイルのみを解凍できます。"
                )
    except zipfile.BadZipFile:
        raise zipfile.BadZipFile(
            f"エラー: '{zip_filepath}' は有効なZIPファイルではありません。"
        )

    password = getpass.getpass(
        f"'{zip_filepath}' の解凍パスワードを入力してください: "
    ).encode("utf-8")

    if extract_dir is None:
        extract_dir = zip_filepath.parent / zip_filepath.stem.replace("_encrypted", "")

    # 抽出されたファイルを追跡
    extracted_files: set[Path] = set()

    def cleanup_extracted_files() -> None:
        """解凍処理中に作成されたファイルのみを削除"""
        for file_path in extracted_files:
            if file_path.exists():
                if file_path.is_file():
                    file_path.unlink()
                else:
                    import shutil

                    shutil.rmtree(file_path)

    try:
        # ディレクトリが存在しない場合のみ作成
        extract_dir.mkdir(parents=True, exist_ok=True)
        extracted_files.add(extract_dir)

        with zipfile.ZipFile(zip_filepath, "r") as zf:
            with zf.open("metadata.encrypted") as metadata_file:
                encrypted_metadata = metadata_file.read()

            try:
                # メタデータを復号化するためのkeyとfernetを作成
                metadata_salt_path = next(
                    name for name in zf.namelist() if name.endswith("metadata.salt")
                )
                with zf.open(metadata_salt_path) as salt_file:
                    metadata_salt = salt_file.read()

                key, _ = generate_key_from_password(password, metadata_salt)
                metadata_fernet = Fernet(key)

                try:
                    decrypted_metadata = metadata_fernet.decrypt(encrypted_metadata)
                    metadata = json.loads(decrypted_metadata.decode("utf-8"))
                    common_salt = base64.b64decode(metadata["common_salt"])
                except Exception as e:
                    cleanup_extracted_files()
                    raise ValueError("エラー: パスワードが間違っています。") from e

                # 共通のソルトでファイルを復号化
                key, _ = generate_key_from_password(password, common_salt)
                file_mapping = metadata["file_mapping"]

                # file_mappingは {元のファイル名: 暗号化されたファイル名} の形式
                for original_path, encrypted_name in file_mapping.items():
                    encrypted_filename = f"{encrypted_name}.encrypted"
                    salt_filename = f"{encrypted_name}.salt"

                    if (
                        salt_filename in zf.namelist()
                        and encrypted_filename in zf.namelist()
                    ):
                        with zf.open(salt_filename) as salt_file:
                            salt = salt_file.read()

                        # 暗号化されたファイルを一時的に保存
                        temp_encrypted = extract_dir / "temp_encrypted"

                        # Windows環境でもパスの区切り文字を統一するためにPosixパスを使用
                        # original_pathがスラッシュを含む場合にWindowsでも正しく処理できるようにする
                        norm_path = Path(original_path.replace("/", os.sep))
                        output_file_path = extract_dir / norm_path

                        # 出力先のディレクトリを作成し、追跡リストに追加
                        output_file_path.parent.mkdir(parents=True, exist_ok=True)
                        extracted_files.add(output_file_path.parent)

                        with (
                            zf.open(encrypted_filename) as encrypted_file,
                            open(temp_encrypted, "wb") as outfile,
                        ):
                            outfile.write(encrypted_file.read())
                        extracted_files.add(temp_encrypted)

                        try:
                            decrypt_file(
                                temp_encrypted,
                                output_file_path,
                                password,
                                salt,
                            )
                            extracted_files.add(output_file_path)
                            if os.path.exists(temp_encrypted):
                                os.remove(temp_encrypted)
                            print(f"'{original_path}' を復号化しました。")
                        except Exception as e:
                            if os.path.exists(temp_encrypted):
                                os.remove(temp_encrypted)
                            if "decrypt" in str(e) or "Invalid token" in str(e):
                                cleanup_extracted_files()
                                raise ValueError(
                                    "エラー: パスワードが間違っています。"
                                ) from e
                            print(
                                f"エラー: '{original_path}' の復号化に失敗しました: {e}"
                            )
                            print(f"    原因: {type(e).__name__}: {str(e)}")
                            continue
                    else:
                        print(
                            f"警告: ファイルまたはソルトが見つかりません: {original_path}"
                        )

            except StopIteration:
                cleanup_extracted_files()
                raise ValueError(
                    "エラー: metadata.saltが見つかりません。ファイルが破損している可能性があります。"
                )
            except Exception as e:
                cleanup_extracted_files()
                if isinstance(e, ValueError):
                    raise
                raise ValueError("エラー: メタデータの復号化に失敗しました。") from e

    except (zipfile.BadZipFile, FileNotFoundError):
        cleanup_extracted_files()
        raise
    except Exception as e:
        cleanup_extracted_files()
        if isinstance(e, ValueError):
            raise
        raise ValueError(
            f"エラー: ZIPファイルの読み込み中にエラーが発生しました: {e}"
        ) from e


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="暗号化ZIPファイルの作成・解凍ツール")
    parser.add_argument(
        "-c",
        "--create",
        dest="operation",
        action="store_const",
        const="create",
        help="暗号化圧縮モード",
    )
    parser.add_argument(
        "-x",
        "--extract",
        dest="operation",
        action="store_const",
        const="extract",
        help="解凍モード",
    )
    parser.add_argument(
        "target",
        help="圧縮対象のパス（-cの場合）またはZIPファイルのパス（-xの場合）",
    )
    parser.add_argument(
        "output",
        nargs="?",
        help="出力先のパス（省略可能。-cの場合はZIPファイル名、-xの場合は解凍先ディレクトリ）",
    )
    parser.add_argument(
        "-e",
        "--encrypt-filenames",
        action="store_true",
        help="ファイル名とディレクトリ名も暗号化する（-cの場合のみ有効）",
    )

    args = parser.parse_args()

    try:
        if not args.operation:
            parser.error("操作を指定してください（-c または -x）")

        if args.operation == "create":
            target_path = Path(args.target).resolve()
            output_zip_path = None
            if args.output:
                output_zip_path = Path(args.output).resolve()
            zip_path = create_secure_encrypted_zip(
                target_path,
                output_zip_path,
                encrypt_filenames=args.encrypt_filenames,
            )
            if args.encrypt_filenames:
                print("注意: ファイル名とディレクトリ名も暗号化されています。")

        elif args.operation == "extract":
            zip_filepath = Path(args.target).resolve()
            extract_dir = None
            if args.output:
                extract_dir = Path(args.output).resolve()
            extract_secure_encrypted_zip(zip_filepath, extract_dir)

    except Exception as e:
        print(f"エラー: {e}")
        sys.exit(1)
