"""Freeze checking and safe evaluation identity; never serializes secrets."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[2]


def fingerprint():
    files = sorted(list((ROOT/'harness_generation').rglob('*.py')) + list((ROOT/'sfg_builder').rglob('*.py')))
    return hashlib.sha256(b''.join(str(p.relative_to(ROOT)).encode()+p.read_bytes() for p in files)).hexdigest()


def assert_frozen(manifest):
    descriptor = json.loads(Path(manifest).read_text())
    expected = descriptor['source_fingerprint']
    if fingerprint() != expected:
        raise RuntimeError('implementation changed: end evaluation; never continue mixed versions')
    if any(hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=value for path,value in descriptor.get('root_runtime_dependencies',{}).items()):
        raise RuntimeError('root runtime dependency changed: end evaluation')


def file_digest(directory):
    return {str(p.relative_to(directory)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(Path(directory).rglob('*')) if p.is_file() and '__pycache__' not in p.parts}
