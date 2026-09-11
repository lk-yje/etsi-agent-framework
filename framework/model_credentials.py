"""Resolve Anthropic-compatible gateway credentials without logging secrets."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Final


_SETTINGS_KEYS: Final = (
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_MODEL",
    "ANTHROPIC_THINKING_MODE",
    "ANTHROPIC_THINKING_BUDGET",
)


def load_model_settings() -> dict[str, str | None]:
    """Load model connection settings, filling only missing items from env.

    ``~/.claude/settings.json`` is a user-owned deployment configuration.  Only
    the Anthropic-compatible connection settings and selected model are read; no values are
    logged or persisted in the test workspace.  Non-empty process environment
    variables are a fallback for an operator who has not configured an item in
    settings.json.  This prevents stale user-level environment variables from
    silently overriding the selected third-party gateway configuration.
    """
    values: dict[str, str] = {}
    settings_path = Path(
        os.environ.get("CLAUDE_SETTINGS_PATH", Path.home() / ".claude" / "settings.json")
    )
    try:
        settings = json.loads(settings_path.read_text(encoding="utf-8"))
        configured = settings.get("env", {})
        if isinstance(configured, dict):
            for key in _SETTINGS_KEYS:
                value = configured.get(key)
                if isinstance(value, str) and value.strip():
                    values[key] = value.strip()
    except (OSError, ValueError, json.JSONDecodeError):
        pass

    for key in _SETTINGS_KEYS:
        value = os.environ.get(key, "").strip()
        if value and key not in values:
            values[key] = value

    return {key: values.get(key) or None for key in _SETTINGS_KEYS}


def load_model_credentials() -> dict[str, str | None]:
    """Return only credential and endpoint values, never the selected model."""
    settings = load_model_settings()
    return {
        key: settings[key]
        for key in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL")
    }
