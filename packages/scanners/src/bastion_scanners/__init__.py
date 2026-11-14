"""Public-only shim. This file does not exist in this form in the product.

The product's ``bastion_scanners`` package holds one adapter per scanner and is not
published. The sandbox runtime needs two plain data types from it, so this shim
re-exports them from ``types.py``, which is the product's file, unchanged.
"""

from __future__ import annotations

from bastion_scanners.types import SandboxStep, StepResult

__all__ = ["SandboxStep", "StepResult"]
