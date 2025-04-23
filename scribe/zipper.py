import base64
import getpass
import os
import sys
import zipfile
from pathlib import Path

import pathspec
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def generate_key_from_password(
    password: bytes,
    salt: bytes | None = None,
) -> tuple[bytes, bytes]:
    """パスワードから暗号化キーを生成します。"""
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


def encrypt_file(input_path: Path, output_path: Path, password: bytes) -> bytes:
    """ファイルを暗号化し、暗号化されたファイルとソルトを返します。"""
    salt = os.urandom(16)
    key, _ = generate_key_from_password(password, salt)
    f = Fernet(key)
    with open(input_path, "rb") as infile:
        data = infile.read()
    encrypted_data = f.encrypt(data)
    with open(output_path, "wb") as outfile:
        outfile.write(salt + encrypted_data)
    return salt


def decrypt_file(
    input_path: Path,
    output_path: Path,
    password: bytes,
    salt: bytes,
) -> None:
    """暗号化されたファイルを復号化します。"""
    key, _ = generate_key_from_password(password, salt)
    f = Fernet(key)
    with open(input_path, "rb") as infile:
        encrypted_data_with_salt = infile.read()
        encrypted_data = encrypted_data_with_salt[16:]
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
        gitignore = pathspec.PathSpec.from_lines(
            pathspec.patterns.GitWildMatchPattern, f.readlines()
        )
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
    relative_path = str(path.relative_to(base_dir))
    return gitignore.match_file(relative_path)


def create_secure_encrypted_zip(target: Path, zip_filename: Path | None = None) -> Path:
    """
    指定されたファイルまたはディレクトリを、cryptographyライブラリで暗号化した上でZIPファイルとして作成します。
    出力ZIPファイル名を省略した場合は自動で命名し、既存ファイル名との重複を避けます。
    .gitignore ファイルが存在する場合は、そのルールに従ってファイルを除外します。
    """
    password_bytes = getpass.getpass("圧縮パスワードを入力してください: ").encode(
        "utf-8"
    )
    password_confirm_bytes = getpass.getpass(
        "圧縮パスワードを再入力してください: "
    ).encode("utf-8")

    if password_bytes != password_confirm_bytes:
        print("エラー: 入力されたパスワードが一致しません。")
        sys.exit(1)

    if zip_filename is None:
        if target.is_file():
            zip_filename_base = target.stem + "_encrypted"
        else:
            zip_filename_base = target.name + "_encrypted"
        zip_filename_suffix = ".zip"
        zip_filename = Path(f"{zip_filename_base}{zip_filename_suffix}")
        counter = 1
        while zip_filename.exists():
            zip_filename = Path(f"{zip_filename_base}_{counter}{zip_filename_suffix}")
            counter += 1

    try:
        with zipfile.ZipFile(
            zip_filename, "w", zipfile.ZIP_DEFLATED, compresslevel=9
        ) as zf:
            if target.is_file():
                encrypted_filepath = target.parent / f"{target.name}.encrypted"
                salt = encrypt_file(target, encrypted_filepath, password_bytes)
                zf.writestr(f"{target.name}.salt", salt)
                zf.write(encrypted_filepath, f"{target.name}.encrypted")
                os.remove(encrypted_filepath)
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

                        relative_path = file_path.relative_to(target)
                        encrypted_filepath = target / f"{relative_path}.encrypted"
                        encrypted_filepath.parent.mkdir(parents=True, exist_ok=True)
                        salt = encrypt_file(
                            file_path, encrypted_filepath, password_bytes
                        )
                        zf.writestr(str(relative_path) + ".salt", salt)
                        zf.write(encrypted_filepath, str(relative_path) + ".encrypted")
                        os.remove(encrypted_filepath)

                print(
                    f"ディレクトリ '{target}' を '{zip_filename}' にパスワード付きで暗号化・圧縮しました。"
                )
            else:
                print(
                    f"エラー: 指定されたパス '{target}' はファイルまたはディレクトリではありません。"
                )
                sys.exit(1)
        return zip_filename
    except Exception as e:
        print(f"エラー: ZIPファイルの作成中にエラーが発生しました: {e}")
        sys.exit(1)


def extract_secure_encrypted_zip(
    zip_filepath: Path,
    extract_dir: Path | None = None,
) -> None:
    """
    cryptographyライブラリで暗号化されたZIPファイルを指定したディレクトリに解凍し、復号化します。
    解凍先ディレクトリが省略された場合は、ZIPファイルと同じ場所に作成します。
    """
    password = getpass.getpass(
        f"'{zip_filepath}' の解凍パスワードを入力してください: "
    ).encode("utf-8")

    if extract_dir is None:
        extract_dir = zip_filepath.parent / zip_filepath.stem.replace("_encrypted", "")
    extract_dir.mkdir(parents=True, exist_ok=True)

    try:
        with zipfile.ZipFile(zip_filepath, "r") as zf:
            for item in zf.namelist():
                if item.endswith(".encrypted"):
                    encrypted_filename = item
                    original_filename = encrypted_filename[:-10]
                    salt_filename = original_filename + ".salt"
                    if salt_filename in zf.namelist():
                        with zf.open(salt_filename) as salt_file:
                            salt = salt_file.read()
                        encrypted_file_path = extract_dir / encrypted_filename
                        output_file_path = extract_dir / original_filename
                        encrypted_file_path.parent.mkdir(parents=True, exist_ok=True)
                        with (
                            zf.open(encrypted_filename) as encrypted_file,
                            open(encrypted_file_path, "wb") as outfile,
                        ):
                            outfile.write(encrypted_file.read())
                        try:
                            decrypt_file(
                                encrypted_file_path, output_file_path, password, salt
                            )
                            os.remove(encrypted_file_path)
                            print(f"'{original_filename}' を復号化しました。")
                        except Exception as e:
                            print(
                                f"エラー: '{original_filename}' の復号化に失敗しました: {e}"
                            )
                    else:
                        print(
                            f"警告: 対応するソルトファイルが見つかりません: {salt_filename}"
                        )
                elif not item.endswith(".salt"):
                    # 暗号化されていないファイルはそのまま展開
                    zf.extract(item, extract_dir)
                    print(f"'{item}' を展開しました (暗号化されていません)。")
    except zipfile.BadZipFile:
        print(f"エラー: '{zip_filepath}' は有効なZIPファイルではありません。")
    except FileNotFoundError:
        print(f"エラー: ファイル '{zip_filepath}' が見つかりません。")
    except Exception as e:
        print(f"エラー: ZIPファイルの読み込み中にエラーが発生しました: {e}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("使用方法:")
        print("  セキュア圧縮: python script.py -c <圧縮対象> [<出力ZIPファイル名>]")
        print("  セキュア解凍: python script.py -x <ZIPファイル>")
        sys.exit(1)

    operation = sys.argv[1]

    if operation == "-c":
        if len(sys.argv) < 3:
            print("使用方法: python script.py -c <圧縮対象> [<出力ZIPファイル名>]")
            sys.exit(1)
        target_path_str = sys.argv[2]
        target_path = Path(target_path_str).resolve()
        output_zip_path = None
        if len(sys.argv) > 3:
            output_zip_path = Path(sys.argv[3]).resolve()
        create_secure_encrypted_zip(target_path, output_zip_path)

    elif operation == "-x":
        if len(sys.argv) != 3:
            print("使用方法: python script.py -x <ZIPファイル>")
            sys.exit(1)
        zip_filepath_str = sys.argv[2]
        zip_filepath = Path(zip_filepath_str).resolve()
        extract_secure_encrypted_zip(zip_filepath)

    else:
        print(
            "エラー: 不明な操作です。'-c' (セキュア圧縮) または '-x' (セキュア解凍) を指定してください。"
        )
        sys.exit(1)
