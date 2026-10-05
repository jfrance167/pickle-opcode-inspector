"""Create inert hand-authored fixtures; never call a serialization loader.

Usage: python scripts/make_demo.py OUTPUT_DIRECTORY
Idempotent for identical contents; refuses to replace different evidence.
"""

from pathlib import Path
import sys


FIXTURES = {
    "hello.pkl": b"\x80\x05\x8c\x05hello.",
    "global-review.pkl": b"ccollections\nCounter\n.",
    "trailing.pkl": b"N.N.",
}


def create(folder: Path):
    """Write small synthetic bytes, preserving existing different files."""
    folder.mkdir(parents=True, exist_ok=True)
    for name, data in FIXTURES.items():
        path = folder / name
        try:
            with path.open("xb") as stream:
                stream.write(data)
        except FileExistsError:
            if path.is_symlink() or not path.is_file():
                raise ValueError("Refusing different existing fixture: " + ascii(str(path)))
            with path.open("rb") as stream:
                existing = stream.read(len(data) + 1)
            if existing != data:
                raise ValueError("Refusing different existing fixture: " + ascii(str(path)))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python scripts/make_demo.py OUTPUT_DIRECTORY")
    create(Path(sys.argv[1]))
