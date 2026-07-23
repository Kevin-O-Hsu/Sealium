# tests/test_ci_workflow.py
"""CI 工作流安全配置回归守护（LOW-005）。

不依赖 PyYAML（避免为单测引入额外依赖、扩大供应链面），用正则验证关键安全
属性：CI 中所有 GitHub Actions 必须钉到不可变 commit SHA。
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CI_YML = REPO_ROOT / ".github" / "workflows" / "ci.yml"
DEPENDABOT_YML = REPO_ROOT / ".github" / "dependabot.yml"

# 匹配 `uses: <ref>`，# 前为 ref，去掉行内注释
_USES_RE = re.compile(r"^\s*uses:\s*([^\s#]+)", re.MULTILINE)
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def test_ci_actions_pinned_to_commit_sha():
    """LOW-005：所有 GitHub Actions 必须 pin 到不可变 commit SHA。

    可变 tag（@v4/@v5）在 tag 被重指或官方账号被攻陷时，可注入恶意代码进入 CI。
    """
    text = CI_YML.read_text(encoding="utf-8")
    refs = [m.group(1) for m in _USES_RE.finditer(text)]
    assert refs, "ci.yml 未找到任何 uses: 行"
    for ref in refs:
        assert "@" in ref, f"action 缺少 @ref: {ref}"
        repo, _, version = ref.partition("@")
        assert _SHA_RE.match(version), (
            f"{repo} 未 pin 到 commit SHA（当前 {version!r}）；"
            "可变 tag 在 tag 被重指/账号被攻陷时可注入恶意代码"
        )


def test_dependabot_maintains_github_actions_updates():
    """LOW-005：Dependabot 监控 github-actions，周期性升级已 pin 的 SHA。"""
    assert DEPENDABOT_YML.exists(), "缺少 .github/dependabot.yml"
    text = DEPENDABOT_YML.read_text(encoding="utf-8")
    assert "github-actions" in text
    assert "updates" in text
