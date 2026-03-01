#!/usr/bin/env python3
"""Download/extract GitHub zip archives and automatically cryptographically seal contents.

The extracted files remain unmodified so runtime behavior is preserved.
During extraction, the tool always creates an encrypted integrity manifest.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import pathlib
import shutil
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DEFAULT_SEAL_KEY_B64 = "uPs8Q_C_nBEGtssLsy5cazP2PghacquTQ76hHL2FMiw="


@dataclass(frozen=True)
class SealArtifact:
    manifest_path: pathlib.Path
    nonce_path: pathlib.Path
    key_b64: str


def _download_zip(url: str, destination: pathlib.Path) -> pathlib.Path:
    destination.mkdir(parents=True, exist_ok=True)
    zip_path = destination / "archive.zip"
    request = Request(url, headers={"User-Agent": "sentinel-containment/zip-sealer"})
    with urlopen(request) as response, zip_path.open("wb") as handle:
        shutil.copyfileobj(response, handle)
    return zip_path


def _safe_extract(zip_path: pathlib.Path, output_dir: pathlib.Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path) as archive:
        resolved_output = output_dir.resolve()
        for member in archive.infolist():
            resolved_member = (output_dir / member.filename).resolve()
            if not str(resolved_member).startswith(str(resolved_output)):
                raise ValueError(f"Unsafe zip member path: {member.filename}")
        archive.extractall(output_dir)


def _iter_files(root: pathlib.Path):
    for path in sorted(root.rglob("*")):
        if path.is_file() and ".seal" not in path.parts:
            yield path


def _build_manifest(extracted_root: pathlib.Path) -> dict:
    files = []
    for path in _iter_files(extracted_root):
        relative = path.relative_to(extracted_root).as_posix()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        stat = path.stat()
        files.append(
            {
                "path": relative,
                "sha256": digest,
                "size": stat.st_size,
                "mtime": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            }
        )

    return {
        "algorithm": "AES-256-GCM",
        "note": "AES-800 is not a standardized cipher variant; AES-256-GCM is used.",
        "created_at": datetime.now(tz=timezone.utc).isoformat(),
        "file_count": len(files),
        "files": files,
    }


def _seal_manifest(manifest: dict, seal_dir: pathlib.Path, key_b64: str) -> SealArtifact:
    seal_dir.mkdir(parents=True, exist_ok=True)
    key = base64.urlsafe_b64decode(key_b64)
    if len(key) != 32:
        raise ValueError("Key must decode to exactly 32 bytes for AES-256.")

    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    plaintext = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    manifest_path = seal_dir / "manifest.enc"
    nonce_path = seal_dir / "seal_meta.json"
    manifest_path.write_bytes(ciphertext)
    nonce_path.write_text(
        json.dumps(
            {
                "algorithm": "AES-256-GCM",
                "nonce_b64": base64.urlsafe_b64encode(nonce).decode("ascii"),
            },
            indent=2,
        )
    )
    return SealArtifact(manifest_path=manifest_path, nonce_path=nonce_path, key_b64=key_b64)


def extract_and_seal(zip_path: pathlib.Path, output_dir: pathlib.Path, key_b64: str = DEFAULT_SEAL_KEY_B64) -> SealArtifact:
    _safe_extract(zip_path, output_dir)
    manifest = _build_manifest(output_dir)
    return _seal_manifest(manifest, output_dir / ".seal", key_b64)


def _make_zip_url(repo: str, ref: str) -> str:
    return f"https://github.com/{repo}/archive/refs/heads/{ref}.zip"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", help="GitHub repo in owner/name format")
    parser.add_argument("--ref", default="main", help="Git ref/branch for zip download (default: main)")
    parser.add_argument("--url", help="Direct zip URL override")
    parser.add_argument("--zip", help="Path to an already-downloaded zip archive")
    parser.add_argument("--output", required=True, help="Directory where the zip should be extracted")
    parser.add_argument(
        "--key",
        default=DEFAULT_SEAL_KEY_B64,
        help="Base64 key for AES-256-GCM sealing. Defaults to the fixed high-security key.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_dir = pathlib.Path(args.output).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.zip:
        zip_path = pathlib.Path(args.zip).resolve()
        download_url = None
    else:
        if not args.repo and not args.url:
            raise ValueError("Provide either --zip, --repo, or --url.")
        download_url = args.url or _make_zip_url(args.repo, args.ref)
        with tempfile.TemporaryDirectory(prefix="gh-zip-seal-") as tmpdir:
            temp_root = pathlib.Path(tmpdir)
            zip_path = _download_zip(download_url, temp_root)
            artifact = extract_and_seal(zip_path, output_dir, args.key)
            print(f"Downloaded: {download_url}")
            print(f"Extracted to: {output_dir}")
            print(f"Encrypted manifest: {artifact.manifest_path}")
            print(f"Seal metadata: {artifact.nonce_path}")
            print(f"AES-256 key (base64): {artifact.key_b64}")
            return 0

    artifact = extract_and_seal(zip_path, output_dir, args.key)
    print(f"Extracted from local zip: {zip_path}")
    print(f"Extracted to: {output_dir}")
    print(f"Encrypted manifest: {artifact.manifest_path}")
    print(f"Seal metadata: {artifact.nonce_path}")
    print(f"AES-256 key (base64): {artifact.key_b64}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
