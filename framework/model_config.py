"""Resolve the ETSI pipeline model from user-owned runtime configuration."""

from framework.model_credentials import load_model_settings


def get_configured_model() -> str:
    """Return the selected model or fail before any agent work begins."""
    model = load_model_settings().get("ANTHROPIC_MODEL")
    if not model:
        raise RuntimeError(
            "未配置模型：请在 ~/.claude/settings.json 的 env 中设置 ANTHROPIC_MODEL。"
        )
    return model
