#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""没有 git 通道时用 GitHub REST API 推一次提交（blob→tree→commit→ref）。

用法: python push_via_api.py <repo_dir> [--dry]
只推 HEAD 相对 origin/<branch> 的那一个（或几个）提交涉及的文件，base_tree 用远端当前树，
所以不会覆盖远端其它内容。
"""
import base64
import json
import subprocess
import sys
import urllib.request

OWNER_REPO = "knowlily/m6-os11-ksu"
API = "https://api.github.com"


def sh(*args, cwd=None):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, check=True).stdout


def token():
    return sh("gh", "auth", "token").strip()


def api(method, path, payload=None, tok=None):
    req = urllib.request.Request(
        API + path,
        method=method,
        data=None if payload is None else json.dumps(payload).encode(),
        headers={
            "Authorization": f"Bearer {tok}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
            "User-Agent": "hermes-push",
        },
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        body = r.read()
        return json.loads(body) if body else {}


def main():
    repo = sys.argv[1]
    dry = "--dry" in sys.argv
    tok = token()

    branch = sh("git", "rev-parse", "--abbrev-ref", "HEAD", cwd=repo).strip()
    head = sh("git", "rev-parse", "HEAD", cwd=repo).strip()
    parent = sh("git", "rev-parse", "HEAD~1", cwd=repo).strip()
    msg = sh("git", "log", "-1", "--pretty=%B", cwd=repo).strip()
    changed = [l.split("\t", 1)[1] for l in
               sh("git", "diff", "--name-status", f"{parent}..{head}", cwd=repo).strip().splitlines()]

    print(f"branch={branch} head={head[:9]} parent={parent[:9]} files={len(changed)}")
    for f in changed:
        print("  ", f)
    if dry:
        return 0

    ref = api("GET", f"/repos/{OWNER_REPO}/git/ref/heads/{branch}", tok=tok)
    remote_sha = ref["object"]["sha"]
    remote_tree = api("GET", f"/repos/{OWNER_REPO}/git/commits/{remote_sha}", tok=tok)["tree"]["sha"]
    print(f"远程 {branch} = {remote_sha[:9]}")

    entries = []
    for f in changed:
        p = f"{repo}/{f}"
        try:
            data = open(p, "rb").read()
        except FileNotFoundError:
            entries.append({"path": f, "mode": "100644", "type": "blob", "sha": None})  # 删除
            continue
        blob = api("POST", f"/repos/{OWNER_REPO}/git/blobs",
                   {"content": base64.b64encode(data).decode(), "encoding": "base64"}, tok=tok)
        entries.append({"path": f, "mode": "100644", "type": "blob", "sha": blob["sha"]})
        print(f"   blob {f} {len(data)}B")

    tree = api("POST", f"/repos/{OWNER_REPO}/git/trees",
               {"base_tree": remote_tree, "tree": [e for e in entries if e["sha"]]}, tok=tok)
    commit = api("POST", f"/repos/{OWNER_REPO}/git/commits",
                 {"message": msg, "tree": tree["sha"], "parents": [remote_sha]}, tok=tok)
    api("PATCH", f"/repos/{OWNER_REPO}/git/refs/heads/{branch}", {"sha": commit["sha"], "force": False}, tok=tok)
    print(f"已推送 {commit['sha'][:9]}")
    print(commit["html_url"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
