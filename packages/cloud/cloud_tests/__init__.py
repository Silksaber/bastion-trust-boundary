"""The cloud provider suite.

A distinct package name for the reason ``pyproject.toml`` records: several test roots
that all called themselves ``tests`` would resolve to one module name and every
conftest but the first would silently vanish.
"""
