#!/usr/bin/env python3
"""Fetch retired CTF challenges to your machine at a pinned commit.

Why this exists
---------------
The challenge archives this course uses are authoritative but mostly
*unlicensed* (the organisers published them for practice). So we do **not**
copy any challenge file into this repository. Instead this script pulls each
challenge, at an exact commit, into ``challenges/<name>/`` (which is
git-ignored). You run it once per challenge before solving it.

Usage
-----
    python challenges/fetch.py <name> [<name> ...]   # specific challenges
    python challenges/fetch.py --all                 # everything in the toml
    python challenges/fetch.py --category crypto     # a whole category
    python challenges/fetch.py --list                # show the catalogue

It is idempotent: already-downloaded files are skipped unless ``--force``.
Primary method is the GitHub REST API + raw.githubusercontent.com at the
commit; if that is unavailable it falls back to a shallow sparse ``git``
checkout at the same commit.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib  # type: ignore

HERE = os.path.dirname(os.path.abspath(__file__))
TOML_PATH = os.path.join(HERE, "challenges.toml")
# Downloads land next to this script by default; override for out-of-tree verification.
DEST_ROOT = os.environ.get("CTFKIT_FETCH_DEST", HERE)
GITHUB_API = "https://api.github.com"
RAW = "https://raw.githubusercontent.com"


def load_catalogue() -> dict:
    with open(TOML_PATH, "rb") as fh:
        return tomllib.load(fh)


def _api_get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "ctfkit-fetch"})
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read()


def list_files_via_api(repo: str, commit: str, path: str) -> list[str]:
    """Return every file path under ``path`` using the git-tree API (one call)."""
    url = f"{GITHUB_API}/repos/{repo}/git/trees/{commit}?recursive=1"
    data = json.loads(_api_get(url))
    prefix = path.rstrip("/") + "/"
    files = []
    for entry in data.get("tree", []):
        if entry["type"] != "blob":
            continue
        p = entry["path"]
        if p == path or p.startswith(prefix):
            files.append(p)
    return files


def download_raw(repo: str, commit: str, repo_path: str, dest: str, force: bool) -> bool:
    """Download one file via raw.githubusercontent.com. Returns True if written."""
    if os.path.exists(dest) and not force:
        return False
    url = f"{RAW}/{repo}/{commit}/" + urllib.parse.quote(repo_path)
    req = urllib.request.Request(url, headers={"User-Agent": "ctfkit-fetch"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        blob = resp.read()
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "wb") as fh:
        fh.write(blob)
    return True


def fetch_via_api(name: str, meta: dict, force: bool) -> int:
    repo, commit, path = meta["repo"], meta["commit"], meta["path"]
    files = list_files_via_api(repo, commit, path)
    if not files:
        raise RuntimeError(f"no files found under {repo}:{path}@{commit[:10]}")
    out_root = os.path.join(DEST_ROOT, name)
    written = 0
    for repo_path in files:
        rel = os.path.relpath(repo_path, path)
        dest = os.path.join(out_root, rel)
        if download_raw(repo, commit, repo_path, dest, force):
            written += 1
    print(f"  [{name}] {len(files)} file(s) under {path} "
          f"({written} downloaded, {len(files) - written} cached)")
    return written


def fetch_via_git(name: str, meta: dict, force: bool) -> int:
    """Fallback: shallow sparse checkout at the commit."""
    repo, commit, path = meta["repo"], meta["commit"], meta["path"]
    out_root = os.path.join(DEST_ROOT, name)
    work = os.path.join(DEST_ROOT, f".git-{name}")
    if os.path.exists(work):
        shutil.rmtree(work)
    url = f"https://github.com/{repo}.git"
    subprocess.run(["git", "clone", "--filter=blob:none", "--no-checkout",
                    "--depth", "1", url, work], check=True)
    subprocess.run(["git", "-C", work, "fetch", "--depth", "1", "origin", commit],
                   check=True)
    subprocess.run(["git", "-C", work, "sparse-checkout", "init", "--cone"], check=True)
    subprocess.run(["git", "-C", work, "sparse-checkout", "set", path], check=True)
    subprocess.run(["git", "-C", work, "checkout", commit], check=True)
    src = os.path.join(work, path)
    if os.path.isdir(out_root) and force:
        shutil.rmtree(out_root)
    shutil.copytree(src, out_root, dirs_exist_ok=True)
    shutil.rmtree(work)
    n = sum(len(f) for _, _, f in os.walk(out_root))
    print(f"  [{name}] fetched via git sparse checkout ({n} files)")
    return n


def fetch_one(name: str, meta: dict, force: bool) -> None:
    print(f"fetching {name}  <-  {meta['repo']}:{meta['path']}@{meta['commit'][:10]}")
    try:
        fetch_via_api(name, meta, force)
    except (urllib.error.URLError, RuntimeError, TimeoutError) as exc:
        print(f"  API path failed ({exc}); falling back to git sparse checkout")
        fetch_via_git(name, meta, force)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("names", nargs="*", help="challenge names to fetch")
    ap.add_argument("--all", action="store_true", help="fetch every challenge")
    ap.add_argument("--category", help="fetch all challenges in a category")
    ap.add_argument("--list", action="store_true", help="list the catalogue and exit")
    ap.add_argument("--force", action="store_true", help="re-download cached files")
    args = ap.parse_args(argv)

    catalogue = load_catalogue()

    if args.list:
        for name, meta in sorted(catalogue.items(), key=lambda kv: kv[1]["category"]):
            svc = "service" if meta.get("needs_service") else "static "
            print(f"  {meta['category']:9} {svc}  {name:28} {meta['difficulty']}")
        return 0

    selected: dict = {}
    if args.all:
        selected = catalogue
    elif args.category:
        selected = {k: v for k, v in catalogue.items()
                    if v["category"] == args.category}
        if not selected:
            print(f"no challenges in category {args.category!r}", file=sys.stderr)
            return 2
    else:
        for name in args.names:
            if name not in catalogue:
                print(f"unknown challenge {name!r} (try --list)", file=sys.stderr)
                return 2
            selected[name] = catalogue[name]

    if not selected:
        ap.print_help()
        return 1

    for name, meta in selected.items():
        fetch_one(name, meta, args.force)
    print(f"done: {len(selected)} challenge(s) in {DEST_ROOT}/<name>/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
