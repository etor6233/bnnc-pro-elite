"""Publication state machine. Network connectivity never implies LIVE."""

from __future__ import annotations

from enum import StrEnum


class BookState(StrEnum):
    EMPTY = "EMPTY"
    SYNCING = "SYNCING"
    LIVE = "LIVE"
    GAP = "GAP"
    STALE = "STALE"
    INVALID = "INVALID"
    RESYNCING = "RESYNCING"
    STOPPED = "STOPPED"


class IllegalTransition(ValueError):
    pass


_ALLOWED: dict[BookState, frozenset[BookState]] = {
    BookState.EMPTY: frozenset({BookState.SYNCING, BookState.STOPPED}),
    BookState.SYNCING: frozenset({BookState.LIVE, BookState.GAP, BookState.INVALID, BookState.STOPPED}),
    BookState.LIVE: frozenset({BookState.GAP, BookState.STALE, BookState.INVALID, BookState.STOPPED}),
    BookState.GAP: frozenset({BookState.RESYNCING, BookState.STOPPED}),
    BookState.STALE: frozenset({BookState.RESYNCING, BookState.STOPPED}),
    BookState.INVALID: frozenset({BookState.RESYNCING, BookState.STOPPED}),
    BookState.RESYNCING: frozenset({BookState.LIVE, BookState.GAP, BookState.INVALID, BookState.STOPPED}),
    BookState.STOPPED: frozenset(),
}


def transition(current: BookState, target: BookState) -> BookState:
    if target not in _ALLOWED[current]:
        raise IllegalTransition(f"illegal book transition: {current} -> {target}")
    return target

