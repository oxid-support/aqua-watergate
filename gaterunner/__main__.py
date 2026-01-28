"""Entry point for running gaterunner as a module: python -m gaterunner"""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
