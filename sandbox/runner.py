"""Opt-in Linux Bubblewrap fixture isolation. No fallback to unsandboxed execution."""
import json
import pathlib
import shutil
import subprocess
import sys

BWRAP = shutil.which("bwrap")
FIXTURE = pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "sandbox_probe.py"

def run_probe():
    if not BWRAP:
        raise RuntimeError("bubblewrap unavailable; refusing unsandboxed execution")
    command = [
        BWRAP, "--die-with-parent", "--unshare-all",
        "--ro-bind", "/usr", "/usr",
        "--ro-bind", "/lib", "/lib",
        "--ro-bind", "/lib64", "/lib64",
        "--proc", "/proc", "--dev", "/dev",
        "--tmpfs", "/tmp", "--tmpfs", "/home",
        "--ro-bind", str(FIXTURE), "/probe.py",
        "--chdir", "/tmp", "/usr/bin/python3", "/probe.py"
    ]
    p = subprocess.run(command, text=True, capture_output=True, timeout=10)
    if p.returncode != 0:
        raise RuntimeError(f"sandbox probe failed (exit={p.returncode}): {p.stderr.strip()}")
    return json.loads(p.stdout)

if __name__ == "__main__":
    print(json.dumps(run_probe(), indent=2, sort_keys=True))
