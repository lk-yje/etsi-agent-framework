"""Installed command-line entry point for ETSI Agent Framework."""

from run_pipeline import main as _run_pipeline_main


def main() -> None:
    """Delegate the installed ``etsi-framework`` command to run_pipeline.py."""
    _run_pipeline_main()


if __name__ == "__main__":
    main()
