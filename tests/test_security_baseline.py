"""Repository-local credential hygiene checks."""

import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_env_template_contains_placeholders_not_key_like_secret():
    template = (PROJECT_ROOT / ".env.template").read_text(encoding="utf-8")

    assert "ANTHROPIC_API_KEY=YOUR_KEY_HERE" in template
    assert not re.search(r"(?i)ANTHROPIC_API_KEY\s*=\s*['\"]?sk-[A-Za-z0-9_-]{12,}", template)


def test_private_env_files_are_gitignored():
    gitignore = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()

    assert ".env" in gitignore
    assert ".env.local" in gitignore
