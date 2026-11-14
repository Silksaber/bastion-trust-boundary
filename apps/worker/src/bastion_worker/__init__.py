"""The scan worker.

Arq consumers that clone a repository, run every applicable scanner inside a sandbox
with no network namespace, normalize what comes back, and reconcile it against what is
already known.

Start it with ``arq bastion_worker.main.WorkerSettings``.
"""

from __future__ import annotations

__all__: list[str] = []
