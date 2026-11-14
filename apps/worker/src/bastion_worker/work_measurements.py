"""Public-only shim. This file does not exist in this form in the product.

In the product, ``measure_work`` records how long each sandbox phase took against the
scan it belongs to, in the database. That bookkeeping is not part of the isolation
boundary and is not published. The sandbox runtime calls it in two places, so this shim
keeps the call and records nothing.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

__all__ = ["measure_work"]


@asynccontextmanager
async def measure_work(operation: str) -> AsyncIterator[dict[str, int | float | None]]:
    """Yield a scratch dictionary and discard it."""
    del operation
    yield {}
