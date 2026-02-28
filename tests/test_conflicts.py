from pathlib import Path
import re


CONFLICT_PATTERN = re.compile(r"^(<<<<<<< .+|=======|>>>>>>> .+)$", re.MULTILINE)


def test_no_merge_conflict_markers_present():
    root = Path(__file__).resolve().parents[1]
    skip_dirs = {".git", ".venv", "__pycache__", ".pytest_cache"}
    offenders: list[str] = []

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in skip_dirs for part in path.parts):
            continue
        if path.suffix in {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pyc"}:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except Exception:
            continue
        if CONFLICT_PATTERN.search(content):
            offenders.append(str(path.relative_to(root)))

    assert not offenders, f"Found merge conflict markers in files: {offenders}"
