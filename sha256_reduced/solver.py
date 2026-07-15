"""Optional Z3 integration used by the SAT/SMT reproduction pipeline."""

from __future__ import annotations

from typing import Any


class MissingSolverError(RuntimeError):
    """Raised when a solver-backed command is used without z3-solver."""


def require_z3() -> Any:
    try:
        import z3  # type: ignore[import-not-found]
    except ImportError as exc:
        raise MissingSolverError(
            "z3-solver is required for SAT/SMT search commands. "
            "Install it with `python3 -m pip install -r requirements.txt`."
        ) from exc
    return z3


def bit(expr: Any, index: int) -> Any:
    z3 = require_z3()
    return z3.Extract(index, index, expr)
