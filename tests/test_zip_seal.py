import base64
import json
import pathlib
import zipfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from scripts.download_and_seal_github_zip import (
    _build_manifest,
    _generate_key_b64,
    _safe_extract,
    _seal_manifest,
    extract_and_seal,
)


def test0_extract_auto_seals_with_random_key(tmp_path: pathlib.Path):
    zip_path = tmp_path / "sample.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("repo-main/hello.txt", "hello")

    extracted = tmp_path / "out"
    artifact = extract_and_seal(zip_path, extracted)

    assert len(base64.urlsafe_b64decode(artifact.key_b64)) == 32
    assert (extracted / ".seal" / "manifest.enc").exists()
    assert (extracted / ".seal" / "seal_meta.json").exists()


def test_generated_keys_are_unique_and_valid_length():
    key_a = _generate_key_b64()
    key_b = _generate_key_b64()

    assert key_a != key_b
    assert len(base64.urlsafe_b64decode(key_a)) == 32
    assert len(base64.urlsafe_b64decode(key_b)) == 32


def test_extract_and_seal_manifest_roundtrip(tmp_path: pathlib.Path):
    zip_path = tmp_path / "sample.zip"
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "hello.txt").write_text("hello")

    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.write(source_dir / "hello.txt", arcname="repo-main/hello.txt")

    extracted = tmp_path / "out"
    _safe_extract(zip_path, extracted)
    manifest = _build_manifest(extracted)
    key_b64 = _generate_key_b64()
    artifact = _seal_manifest(manifest, extracted / ".seal", key_b64)

    meta = json.loads(artifact.nonce_path.read_text())
    nonce = base64.urlsafe_b64decode(meta["nonce_b64"])
    key = base64.urlsafe_b64decode(artifact.key_b64)
    plaintext = AESGCM(key).decrypt(nonce, artifact.manifest_path.read_bytes(), None)
    recovered = json.loads(plaintext.decode("utf-8"))

    assert recovered["file_count"] == 1
    assert recovered["files"][0]["path"] == "repo-main/hello.txt"


def test_extract_rejects_path_traversal(tmp_path: pathlib.Path):
    zip_path = tmp_path / "evil.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("../../escape.txt", "bad")

    out = tmp_path / "out"

    try:
        _safe_extract(zip_path, out)
        assert False, "Expected ValueError for path traversal"
    except ValueError as error:
        assert "Unsafe zip member path" in str(error)
