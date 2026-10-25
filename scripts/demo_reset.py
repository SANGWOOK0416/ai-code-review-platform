"""라이브 데모 브랜치를 준비 상태로 만들고(처음 준비에도 사용), 데모로 연 PR을 닫는다.

준비 상태 = 원격 브랜치가 'origin/main + 장면 파일' 커밋 하나. 현장에서는 GitHub에서
"Compare & pull request" → "Create pull request"만 누르면 된다.

사용 예:
    python scripts/demo_reset.py            # 계획만 출력 (아무것도 바꾸지 않음)
    python scripts/demo_reset.py --yes      # 실제 실행
    python scripts/demo_reset.py --yes --scene 1

안전장치:
  - 허용 목록(demo_common.SCENES의 두 브랜치) 밖의 브랜치는 push도, PR 닫기도 하지 않는다.
    main은 어떤 경우에도 대상이 아니다.
  - 사용자의 작업 트리·로컬 브랜치·인덱스는 건드리지 않는다 (임시 인덱스로 커밋을 만든다).
  - 원격 브랜치는 조회한 시점 값과 같을 때만 덮어쓴다 (--force-with-lease).
  - 닫는 PR은 head가 허용 브랜치이고 base가 main인 열린 PR뿐이다.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from demo_common import BASE_BRANCH, DEFAULT_REPO, SCENES, GitHubAPIError, github_api  # noqa: E402

ALLOWED_BRANCHES = frozenset(SCENES)
COMMIT_TRAILER = "\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"


class UnsafeTarget(RuntimeError):
    pass


def ensure_allowed(branch: str) -> None:
    if branch not in ALLOWED_BRANCHES or branch == BASE_BRANCH or not branch.startswith("demo/live-"):
        raise UnsafeTarget(f"허용 목록 밖의 브랜치는 건드리지 않음: {branch!r}")


def git(*args: str, env: dict | None = None, check: bool = True) -> str:
    proc = subprocess.run(["git", *args], capture_output=True, text=True, encoding="utf-8", env=env)
    if check and proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args[:2])} 실패: {proc.stderr.strip()[:300]}")
    return proc.stdout.strip()


def remote_sha(branch: str) -> str | None:
    """main()의 git fetch 직후 원격 추적 ref 기준. 그 사이 원격이 바뀌었다면 push의 lease가 거절한다."""
    out = git("rev-parse", "--verify", "--quiet", f"refs/remotes/origin/{branch}", check=False)
    return out or None


def build_target_tree(base_sha: str, source_ref: str, paths: list) -> str:
    """origin/main 트리에 장면 파일을 얹은 트리를 임시 인덱스로 만든다 (작업 트리 무관)."""
    with tempfile.TemporaryDirectory(prefix="demo_reset_") as tmp:
        env = {**os.environ, "GIT_INDEX_FILE": str(Path(tmp) / "index")}
        git("read-tree", base_sha, env=env)
        for path in paths:
            entry = git("ls-tree", source_ref, "--", path)
            if not entry:
                raise RuntimeError(f"{source_ref}에 {path}가 없음")
            mode, _, blob_and_path = entry.partition(" ")
            blob = blob_and_path.split()[1]
            git("update-index", "--add", "--cacheinfo", f"{mode},{blob},{path}", env=env)
        return git("write-tree", env=env)


def branch_state(branch: str, base_sha: str, target_tree: str):
    """(원격 sha, 상태 설명, 리셋 필요 여부)."""
    current = remote_sha(branch)
    if current is None:
        return None, "원격에 없음 → 새로 만듦", True
    tree = git("rev-parse", f"{current}^{{tree}}")
    parents = git("rev-list", "--parents", "-n", "1", current).split()[1:]
    if tree == target_tree and parents == [base_sha]:
        return current, "준비 상태 (변경 없음)", False
    return current, "준비 상태와 다름 → origin/main + 장면 파일로 다시 만듦", True


def open_demo_prs(repo: str) -> list:
    """base=main으로 열린 PR 중 head가 허용 브랜치이고 같은 저장소에서 온 것만."""
    prs = github_api("GET", f"/repos/{repo}/pulls?state=open&base={BASE_BRANCH}&per_page=100")
    return [
        pr for pr in prs
        if pr["head"]["ref"] in ALLOWED_BRANCHES
        and pr["base"]["ref"] == BASE_BRANCH
        and (pr["head"].get("repo") or {}).get("full_name") == repo
    ]


def reset_scene(repo: str, branch: str, base_sha: str, apply: bool, all_open_prs: list) -> bool:
    ensure_allowed(branch)
    scene = SCENES[branch]
    print(f"\n== {branch} ==")

    prs = [pr for pr in all_open_prs if pr["head"]["ref"] == branch]
    if not prs:
        print("  열린 데모 PR 없음")
    for pr in prs:
        ensure_allowed(pr["head"]["ref"])
        if apply:
            github_api("PATCH", f"/repos/{repo}/pulls/{pr['number']}", {"state": "closed"})
            print(f"  PR #{pr['number']} 닫음 ({pr['title']})")
        else:
            print(f"  (계획) PR #{pr['number']} 닫기 ({pr['title']})")

    target_tree = build_target_tree(base_sha, scene["source_ref"], scene["paths"])
    current, description, needs_reset = branch_state(branch, base_sha, target_tree)
    print(f"  브랜치: {description}")
    if not needs_reset:
        return True
    if not apply:
        print("  (계획) 브랜치를 준비 상태로 push")
        return True

    message = f"{scene['title']}\n\n데모 리허설용 준비 커밋 — main 대비 장면 파일만 추가 (scripts/demo_reset.py)" + COMMIT_TRAILER
    commit = git("commit-tree", target_tree, "-p", base_sha, "-m", message)
    ensure_allowed(branch)
    lease = f"--force-with-lease=refs/heads/{branch}:{current or ''}"
    git("push", "--quiet", lease, "origin", f"{commit}:refs/heads/{branch}")
    print(f"  push 완료: {commit[:7]} (main {base_sha[:7]} + {len(scene['paths'])}개 파일)")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="데모 브랜치 준비/리셋 + 데모 PR 닫기")
    parser.add_argument("--repo", default=DEFAULT_REPO)
    parser.add_argument("--scene", choices=["1", "2"], help="한 장면만 처리 (기본: 둘 다)")
    parser.add_argument("--yes", action="store_true", help="실제로 실행 (없으면 계획만 출력)")
    args = parser.parse_args()

    branches = [f"demo/live-scene{args.scene}"] if args.scene else sorted(ALLOWED_BRANCHES)
    for branch in branches:
        ensure_allowed(branch)

    # 네트워크 왕복을 줄이려고 fetch는 한 번만 (main + 장면 원본 브랜치 + 데모 브랜치 추적 ref 전부 갱신)
    git("fetch", "--quiet", "origin")
    base_sha = git("rev-parse", f"origin/{BASE_BRANCH}")
    print(f"기준: origin/{BASE_BRANCH} = {base_sha[:7]}" + ("" if args.yes else "  (계획만 출력 — 실행하려면 --yes)"))

    try:
        all_open_prs = open_demo_prs(args.repo)
    except GitHubAPIError as e:
        print(f"[FAIL] 열린 PR 조회 실패: {e}")
        return 1

    results = [reset_scene(args.repo, branch, base_sha, args.yes, all_open_prs) for branch in branches]
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
