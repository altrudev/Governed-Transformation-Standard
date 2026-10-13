"""Build a bounded reviewed GTS runtime bundle without administrator access.

The operator must independently verify the printed bundle digest and source
revision before copying the bundle into root-owned custody. Not attestation.
"""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import subprocess
import tarfile


def git(root, *args):
    result = subprocess.run(["git", "-C", str(root), *args],
                            check=True, capture_output=True, timeout=25)
    return result.stdout


def _allowed(filename):
    parts = PurePosixPath(filename).parts
    if len(parts) != 2:
        return False
    domain, name = parts
    return (domain in {"observer", "broker", "evaluator"} and
            name.endswith(".py") or
            domain == "deployment" and
            (name.endswith(".py") or name.endswith((".service", ".conf"))))


def build(root, dest):
    root = Path(root).resolve()
    dest = Path(dest)
    if git(root, "status", "--porcelain"):
        raise RuntimeError("refusing dirty release source")
    revision = git(root, "rev-parse", "HEAD").decode("ascii").strip()
    if len(revision) != 40:
        raise ValueError("exact source commit is required")
    manifest = []
    tracks = git(root, "ls-files", "--stage", "-z").split(b"\0")
    for line in tracks:
        if not line:
            continue
        prefix, raw_path = line.split(b"\t", 1)
        mode = prefix.split(b" ", 1)[0]
        filename = raw_path.decode("utf-8")
        if not _allowed(filename):
            continue
        # Never package symlink, submodule, executable or non-tracked assets.
        if mode != b"100644" or (root / filename).is_symlink():
            raise ValueError(f"disallowed tracked type: {filename}")
        content = git(root, "show", f"HEAD:{filename}")
        if len(content) > 1024 * 1024:
            raise ValueError("source file exceeds bounded size")
        manifest.append((filename, content))
    must_have = {
        "deployment/bootstrap_host.py",
        "deployment/gts-observer.service",
        "deployment/gts-broker.service",
        "deployment/gts-sockets.tmpfiles.conf",
        "observer/runtime.py", "broker/runtime.py",
        "evaluator/synthetic_acceptance.py"
    }
    if not must_have <= {p for p, _ in manifest}:
        raise ValueError("required runtime module missing")
    for original in ("observer/__init__.py", "broker/__init__.py",
                     "evaluator/__init__.py", "deployment/__init__.py"):
        if original not in {p for p, _ in manifest}:
            raise ValueError(f"missing package initializer: {original}")
    entries = [
        {"path": path, "sha256": hashlib.sha256(payload).hexdigest(),
         "size": len(payload)}
        for path, payload in sorted(manifest)
    ]
    bundle_manifest = {
        "schema": "gts.operator-source-bundle.v1",
        "source_revision": revision,
        "qualification": "UNSIGNED_SOURCE_INTAKE",
        "entries": entries
    }
    source = sorted(manifest)
    source.append(("SOURCE-MANIFEST.json",
                   (json.dumps(bundle_manifest, sort_keys=True,
                               indent=2) + "\n").encode()))
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "wb") as stream:
        with gzip.GzipFile(filename="", fileobj=stream,
                           mode="wb", mtime=0, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|") as archive:
                for name, content in source:
                    info = tarfile.TarInfo(name)
                    info.mode = 0o644
                    info.uid = info.gid = 0
                    info.uname = info.gname = "root"
                    info.mtime = 0
                    info.size = len(content)
                    archive.addfile(info, io.BytesIO(content))
    return {"revision": revision, "files": len(source),
            "archive": str(dest),
            "sha256": hashlib.sha256(dest.read_bytes()).hexdigest()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    opts = ap.parse_args()
    print(json.dumps(build(Path(__file__).resolve().parents[1], opts.out),
                     sort_keys=True))


if __name__ == "__main__":
    main()
