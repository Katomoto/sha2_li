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


def configure_solver_instance(
    solver: Any,
    *,
    timeout_ms: int | None = None,
    random_seed: int | None = None,
    threads: int | None = None,
) -> None:
    """Apply best-effort configuration knobs to a Z3 solver/optimizer."""

    params: list[tuple[str, Any]] = []
    if timeout_ms is not None:
        params.append(("timeout", timeout_ms))
    if random_seed is not None:
        params.extend(
            (
                ("random_seed", random_seed),
                ("sat.random_seed", random_seed),
                ("smt.random_seed", random_seed),
            )
        )
    if threads is not None and threads > 1:
        params.extend(
            (
                ("parallel.enable", True),
                ("threads", threads),
                ("sat.threads", threads),
            )
        )

    for key, value in params:
        try:
            solver.set(key, value)
        except Exception:
            # Z3 parameter support differs across engines and versions. The
            # search code treats these knobs as best-effort hints rather than
            # hard requirements.
            continue
