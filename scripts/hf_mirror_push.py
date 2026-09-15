#!/usr/bin/env python3
"""hf_mirror_push -- same convention as sipa-os-governance/scripts/hf_mirror_push.py,
adapted for this repo (no dataset-specific citation checkers here to run against
the archived tree; eilatsecure has none).

It:
  1. Refuses to run if `git status --porcelain` is not empty.
  2. Resolves HEAD to a single sha and archives *that exact commit's tree*
     via `git archive`, not the working directory.
  3. Writes that sha (plus UTC push time) into MIRROR_PROVENANCE.md -- a
     file that does NOT come out of the archive and carries no .sha256 of
     its own, so the seal never has to be true about the mirror's own past.
  4. Uploads the archived tree plus that one added file as ONE atomic
     commit via upload_folder, with delete_patterns=["*"] so a file
     deleted upstream also disappears from the mirror.

Requires HF_TOKEN in the environment and huggingface_hub installed.
"""
import os
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
HF_REPO_ID = "SoulInPsyAbstract/websecure"


def run(cmd: list[str], **kw) -> str:
    return subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, check=True, **kw).stdout.strip()


def refuse_if_dirty() -> None:
    status = run(["git", "status", "--porcelain"])
    if status:
        print("[hf_mirror_push] REFUSED: working tree is dirty, not pushing a mixed-moment mirror.")
        print(status)
        sys.exit(1)


def current_sha() -> str:
    return run(["git", "rev-parse", "HEAD"])


def commit_timestamp(sha: str) -> str:
    return run(["git", "show", "-s", "--format=%cI", sha])


def archive_commit_to(sha: str, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    archive_path = dest.parent / f"{sha}.tar"
    with open(archive_path, "wb") as f:
        subprocess.run(["git", "archive", "--format=tar", sha], cwd=REPO_ROOT, stdout=f, check=True)
    with tarfile.open(archive_path) as tar:
        tar.extractall(dest, filter="data")
    archive_path.unlink()


def write_provenance_file(tree: Path, sha: str, commit_ts: str) -> str:
    pushed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    content = (
        "# Mirror provenance\n\n"
        "This is not part of the archived repository -- it is written fresh on every "
        "push and carries no `.sha256` seal, deliberately. Every *other* file in this "
        "mirror is a byte-exact `git archive` of one GitHub commit, sealed at that "
        "commit; this file is the one exception, so that the file describing the copy "
        "never has to also be true about the copy's own past.\n\n"
        f"- **Source commit:** [`{sha}`](https://github.com/soulinpsyabstract/eilatsecure/commit/{sha})\n"
        f"- **Committed upstream:** {commit_ts}\n"
        f"- **Pushed to this mirror:** {pushed_at}\n"
        "- **Method:** `git archive` of that exact commit, uploaded as one atomic "
        "commit via `scripts/hf_mirror_push.py`, which refuses to run on a dirty tree.\n"
    )
    (tree / "MIRROR_PROVENANCE.md").write_text(content)
    return f"Mirror GitHub commit {sha} (committed {commit_ts}), pushed {pushed_at}"


def main() -> int:
    refuse_if_dirty()
    sha = current_sha()
    commit_ts = commit_timestamp(sha)
    print(f"[hf_mirror_push] pushing commit {sha} ({commit_ts})")

    with tempfile.TemporaryDirectory() as tmp:
        tree = Path(tmp) / "tree"
        archive_commit_to(sha, tree)

        commit_msg = write_provenance_file(tree, sha, commit_ts)

        from huggingface_hub import HfApi

        token = os.environ.get("HF_TOKEN") or os.environ.get("HF_TOKEN_GRAND")
        if not token:
            print("[hf_mirror_push] REFUSED: no HF_TOKEN in environment.")
            return 1

        api = HfApi(token=token)
        api.upload_folder(
            folder_path=str(tree),
            repo_id=HF_REPO_ID,
            repo_type="dataset",
            commit_message=commit_msg,
            delete_patterns=["*"],
        )
    print(f"[hf_mirror_push] DONE: mirror now projects commit {sha}, single atomic push.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
