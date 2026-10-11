# Disk-backed scratch storage on Prometheus

On this host, `/tmp` is a memory-backed `tmpfs` with `usrquota`. A user can receive errno 122 (disk quota exceeded) despite filesystem-wide free space. Do not disable quota, enlarge tmpfs or delete old test directories without checking for live processes and evidence retention.

Use `sh scripts/run-with-disk-tmp.sh <command>` for GTS workloads. The wrapper creates private directories under `$XDG_STATE_HOME/altru` (default: `~/.local/state/altru`), sets `TMPDIR`, `TMP`, and `TEMP`, and uses umask 077. It does not change the host global /tmp policy. Other Altru/Frequency projects should adopt comparable explicit launchers after their own test suites pass.

For a report, run:

```sh
sh scripts/run-with-disk-tmp.sh python3 -m assurance.full_sweep --report "$HOME/.local/state/altru/reports/gts-full-sweep.json"
```

The audit returns 2 while controls remain disconnected; this is an expected security block, not a storage failure. Do not assume all software honors `TMPDIR`; verify actual temp paths. Inventory old /tmp directories and running processes before any migration or cleanup. Never remove source, signing material or unique audit evidence as a cache.
