# ruff: noqa: PLR1702, TRY301

import base64
import getpass
import json
import os
import shutil
import sys
import zipfile
from pathlib import Path
from typing import Any

import pathspec
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def generate_key_from_password(
    password: bytes,
    salt: bytes | None = None,
) -> tuple[bytes, bytes]:
    """パスワードとソルトから暗号化キーを生成する。

    Args:
        password: パスワードのバイト列
        salt: ソルトのバイト列(省略可能)

    Returns:
        tuple[bytes, bytes]: 生成されたキーとソルト
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
    """ファイルを暗号化し、暗号化済みデータとソルトを返す。

    Returns:
        tuple[bytes, bytes]: (salt, encrypted_data)
    """
    salt = os.urandom(16)
    key, _ = generate_key_from_password(password, salt)
    f = Fernet(key)
    data = Path(input_path).read_bytes()
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
    encrypted_data = Path(input_path).read_bytes()
    decrypted_data = f.decrypt(encrypted_data)
    Path(output_path).write_bytes(decrypted_data)


def load_gitignore_patterns(
    directory: Path,
) -> list[tuple[Path, Any]]:
    """指定ディレクトリの .gitignore を pathspec パターンに変換する。

    Returns:
        list[tuple[Path, pathspec.pattern.Pattern]]:
            (ベースディレクトリ, パターン) のリスト。.gitignore が無ければ空。
    """
    gitignore_path = directory / ".gitignore"
    if not gitignore_path.is_file():
        return []

    patterns: list[tuple[Path, Any]] = []
    with Path(gitignore_path).open(encoding="utf-8") as f:
        # PathSpec を使って各行をパターン化し、pattern.include も保持する
        spec = pathspec.PathSpec.from_lines("gitignore", f)
        patterns.extend((directory, p) for p in spec.patterns)
    return patterns


def is_ignored_by_gitignore(path: Path, patterns: list[tuple[Path, Any]]) -> bool:
    """.gitignore の評価順に従い、最後にマッチしたルールで判定する。

    patterns は (その .gitignore が置かれたディレクトリ, パターン) の順序付きリスト。

    Returns:
        bool: True なら除外対象。
    """
    ignored = False
    for base_dir, pattern in patterns:
        try:
            relative_path = path.relative_to(base_dir).as_posix()
        except ValueError:
            # base_dir の配下でなければスキップ
            continue

        # ディレクトリ専用パターン(末尾スラッシュ)も拾うよう末尾スラッシュ付きで確認
        candidates = [relative_path]
        if path.is_dir():
            candidates.append(f"{relative_path}/")

        if any(pattern.match_file(candidate) for candidate in candidates):
            # include=True は「このパターンにマッチする」を意味する
            # .gitignore では後勝ち。True なら除外、False なら除外しない(!)。
            ignored = bool(pattern.include)
    return ignored


def encrypt_filename(filename: str, fernet: Fernet) -> str:
    """ファイル名を暗号化する。

    Args:
        filename: 暗号化するファイル名
        fernet: 暗号化に使用するFernetオブジェクト

    Returns:
        str: 暗号化されたファイル名(Fernetトークン)

    Raises:
        ValueError: 暗号化に失敗した場合
    """
    try:
        print(f"📩 圧縮: {filename}")
        encrypted_bytes = fernet.encrypt(filename.encode("utf-8"))
        encrypted_name = encrypted_bytes.decode("ascii")
    except Exception as e:
        raise ValueError(f"ファイル名の暗号化に失敗しました: {filename} ({e!s})") from e
    return encrypted_name


def decrypt_filename(encrypted_filename: str, fernet: Fernet) -> str:
    """暗号化されたファイル名を復号化する。

    Args:
        encrypted_filename: 暗号化されたファイル名(Fernetトークン)
        fernet: 復号化に使用するFernetオブジェクト

    Returns:
        str: 復号化されたファイル名

    Raises:
        ValueError: 復号化に失敗した場合
    """
    try:
        print(f"復号化前のファイル名: {encrypted_filename}")
        decrypted_bytes = fernet.decrypt(encrypted_filename.encode("ascii"))
        decrypted_name = decrypted_bytes.decode("utf-8")
        print(f"復号化後のファイル名: {decrypted_name}")
    except Exception as e:
        raise ValueError(
            f"ファイル名の復号化に失敗しました: {encrypted_filename} ({e!s})"
        ) from e
    return decrypted_name


def create_secure_encrypted_zip(  # noqa: PLR0912
    target: Path, zip_filename: Path | None = None, encrypt_filenames: bool = False
) -> Path:
    """指定されたファイルやディレクトリを暗号化してZIPを作成する。

    ファイル名の暗号化にも対応。出力名を省略した場合は自動命名し、既存と重複しないよう連番を付ける。
    .gitignore がある場合はそのルールで除外する。

    Args:
        target: 圧縮対象のファイルまたはディレクトリのパス
        zip_filename: 出力するZIPファイルのパス(省略可能)
        encrypt_filenames: ファイル名を暗号化するかどうか(デフォルトはFalse)

    Returns:
        作成されたZIPファイルのパス

    Raises:
        FileNotFoundError: 指定されたパスが存在しない場合
        ValueError: パスワードが一致しない場合、またはパスの種類が不正な場合
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

    # ファイル暗号化で使う共通ソルト
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
        file_mapping: dict[
            str, str
        ] = {}  # キー: 元のファイル名, 値: 暗号化されたファイル名

        # 内部関数で再帰的に処理
        def _process_directory(
            current_path: Path,
            parent_patterns: list[tuple[Path, Any]],
            zf: zipfile.ZipFile,
        ) -> None:
            # .git ディレクトリは除外
            if current_path.name == ".git":
                return

            # 現在のディレクトリの .gitignore を読み込み、親からのパターンに追加
            current_patterns = list(parent_patterns)
            current_patterns.extend(load_gitignore_patterns(current_path))

            # ディレクトリ内のアイテムを走査
            for item in current_path.iterdir():
                # .gitignore で除外されているかチェック
                if is_ignored_by_gitignore(item, current_patterns):
                    print(f"🚫 除外: {item.relative_to(target)} (.gitignore に一致)")
                    continue

                if item.is_dir():
                    _process_directory(item, current_patterns, zf)
                elif item.is_file():
                    # OSに依存しない形式でパスを扱う
                    relative_path = item.relative_to(target).as_posix()
                    if encrypt_filenames:
                        encrypted_name = encrypt_filename(
                            relative_path, metadata_fernet
                        )
                    else:
                        encrypted_name = relative_path

                    # file_mappingの保存
                    file_mapping[relative_path] = encrypted_name

                    salt, encrypted_bytes = encrypt_file(item, password_bytes)
                    zf.writestr(f"{encrypted_name}.salt", salt)
                    zf.writestr(f"{encrypted_name}.encrypted", encrypted_bytes)

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
                print(f"ファイル '{target}' を '{zip_filename}' に暗号化しました。")
            elif target.is_dir():
                _process_directory(target, [], zf)

                print(f"ディレクトリ '{target}' を '{zip_filename}' に暗号化しました。")
            else:
                raise ValueError(
                    f"指定パス '{target}' はファイルまたはディレクトリではありません。"
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

    except Exception:
        # エラー発生時は作成途中のZIPファイルを削除
        if zip_filename and zip_filename.exists():
            zip_filename.unlink()
        raise

    else:
        return zip_filename


def extract_secure_encrypted_zip(  # noqa: C901, PLR0912
    zip_filepath: Path, extract_dir: Path | None = None
) -> None:
    """暗号化ZIPを解凍し、内容とファイル名を復号する。

    解凍先を省略した場合は ZIP と同じ場所に作成する。

    Args:
        zip_filepath: 解凍するZIPファイルのパス
        extract_dir: 解凍先ディレクトリのパス(省略可能)

    Raises:
        FileNotFoundError: ZIPファイルが見つからない場合
        zipfile.BadZipFile: 無効なZIPファイルの場合
        ValueError: パスワードが間違っている場合、またはファイルが暗号化ZIPではない場合
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
        ) from None

    password = getpass.getpass(
        f"'{zip_filepath}' の解凍パスワードを入力してください: "
    ).encode("utf-8")

    if extract_dir is None:
        extract_dir = zip_filepath.parent / zip_filepath.stem.replace("_encrypted", "")

    # 抽出処理中に「新規作成した」ファイル/ディレクトリだけを追跡
    created_paths: set[Path] = set()

    def cleanup_created_paths() -> None:
        """新規作成物のみを削除し、既存資産は触らない"""
        for file_path in sorted(
            created_paths, key=lambda p: len(p.parts), reverse=True
        ):
            if file_path.exists():
                if file_path.is_file():
                    file_path.unlink()
                else:
                    shutil.rmtree(file_path)

    try:
        # extract_dir を新規作成した場合だけクリーンアップ対象にする
        if not extract_dir.exists():
            extract_dir.mkdir(parents=True, exist_ok=True)
            created_paths.add(extract_dir)

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
                    cleanup_created_paths()
                    raise ValueError("エラー: パスワードが間違っています。") from e

                # 共通のソルトでファイルを復号化
                key, _ = generate_key_from_password(password, common_salt)
                file_mapping = metadata["file_mapping"]

                # file_mappingは {元のファイル名: 暗号化されたファイル名} の形式
                for original_path, encrypted_name in file_mapping.items():
                    encrypted_filename = f"{encrypted_name}.encrypted"
                    salt_filename = f"{encrypted_name}.salt"

                    # 必要なソルト/暗号ファイルが無ければ警告して次へ
                    if (
                        salt_filename not in zf.namelist()
                        or encrypted_filename not in zf.namelist()
                    ):
                        print(f"警告: ソルトまたはファイル欠落: {original_path}")
                        continue

                    with zf.open(salt_filename) as salt_file:
                        salt = salt_file.read()

                    # 暗号化されたファイルを一時的に保存
                    temp_encrypted = extract_dir / "temp_encrypted"

                    # Windows/Posix いずれの区切りでも正しく展開できるよう正規化
                    normalized = original_path.replace("\\", "/").replace("/", os.sep)
                    norm_path = Path(normalized)
                    output_file_path = extract_dir / norm_path

                    # 出力先のディレクトリを作成し、追跡リストに追加
                    if not output_file_path.parent.exists():
                        output_file_path.parent.mkdir(parents=True, exist_ok=True)
                        created_paths.add(output_file_path.parent)

                    try:
                        with zf.open(encrypted_filename) as encrypted_file:
                            Path(temp_encrypted).write_bytes(encrypted_file.read())
                        created_paths.add(temp_encrypted)

                        decrypt_file(
                            temp_encrypted,
                            output_file_path,
                            password,
                            salt,
                        )
                        created_paths.add(output_file_path)
                        print(f"✅ 復号完了: '{original_path}'")
                    except Exception as e:
                        if isinstance(e, InvalidToken) or "Invalid token" in str(e):
                            cleanup_created_paths()
                            raise ValueError(
                                "エラー: パスワードが間違っています。"
                            ) from e
                    finally:
                        if Path(temp_encrypted).exists():
                            Path(temp_encrypted).unlink()

            except StopIteration:
                cleanup_created_paths()
                raise ValueError(
                    "エラー: metadata.saltが見つかりません。"
                    "ファイル破損の可能性があります。"
                ) from None
            except Exception as e:
                cleanup_created_paths()
                if isinstance(e, ValueError):
                    raise
                raise ValueError("エラー: メタデータの復号化に失敗しました。") from e

    except (zipfile.BadZipFile, FileNotFoundError):
        cleanup_created_paths()
        raise
    except Exception as e:
        cleanup_created_paths()
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
        help="圧縮対象のパス(-cの場合)またはZIPファイルのパス(-xの場合)",
    )
    parser.add_argument(
        "output",
        nargs="?",
        help="出力先のパス(省略可能。-cの場合はZIPファイル名、-xの場合は解凍先ディレクトリ)",
    )
    parser.add_argument(
        "-e",
        "--encrypt-filenames",
        action="store_true",
        help="ファイル名とディレクトリ名も暗号化する(-cの場合のみ有効)",
    )

    args = parser.parse_args()

    try:
        if not args.operation:
            parser.error("操作を指定してください(-c または -x)")

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

    except Exception as e:  # noqa: BLE001
        print(f"エラー: {e}")
        sys.exit(1)
