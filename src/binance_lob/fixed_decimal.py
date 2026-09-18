"""Exact base-10 values for prices, quantities, fees and money.

No binary floating-point value is accepted at this boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
import re


_DECIMAL = re.compile(r"^(?P<sign>-?)(?P<whole>0|[1-9][0-9]*)(?:\.(?P<fraction>[0-9]+))?$")

# Canonical string memoization: FixedDecimal is frozen, so a given
# (coefficient, scale) always maps to the same canonical string.  This cache
# removes the per-frame re-formatting storm inside Book.state_digest (measured:
# 41% of the verifier's wall time was __str__).  The cap bounds memory; on
# overflow the cache is cleared (worst case re-computes, never wrong).
_STR_CACHE: dict[tuple[int, int], str] = {}
_STR_CACHE_CAP = 1_000_000


@dataclass(frozen=True, slots=True)
class FixedDecimal:
    coefficient: int
    scale: int

    def __post_init__(self) -> None:
        if self.scale < 0 or self.scale > 18:
            raise ValueError("scale must be between 0 and 18")

    @classmethod
    def parse(cls, text: str, *, max_scale: int = 18) -> "FixedDecimal":
        if not isinstance(text, str):
            raise TypeError("decimal input must be a string")
        match = _DECIMAL.fullmatch(text)
        if match is None:
            raise ValueError(f"invalid plain decimal: {text!r}")
        fraction = match.group("fraction") or ""
        if len(fraction) > max_scale:
            raise ValueError("decimal exceeds allowed scale")
        digits = match.group("whole") + fraction
        coefficient = int(digits)
        if match.group("sign"):
            coefficient = -coefficient
        return cls(coefficient=coefficient, scale=len(fraction))

    def rescale_exact(self, target_scale: int) -> "FixedDecimal":
        if target_scale < 0 or target_scale > 18:
            raise ValueError("target_scale must be between 0 and 18")
        delta = target_scale - self.scale
        if delta >= 0:
            return FixedDecimal(self.coefficient * (10**delta), target_scale)
        divisor = 10 ** (-delta)
        quotient, remainder = divmod(abs(self.coefficient), divisor)
        if remainder:
            raise ValueError("rescale would lose precision")
        if self.coefficient < 0:
            quotient = -quotient
        return FixedDecimal(quotient, target_scale)

    def canonical(self) -> "FixedDecimal":
        coefficient = self.coefficient
        scale = self.scale
        while scale > 0 and coefficient % 10 == 0:
            coefficient //= 10
            scale -= 1
        return FixedDecimal(coefficient, scale)

    def _aligned(self, other: "FixedDecimal") -> tuple[int, int]:
        if not isinstance(other, FixedDecimal):
            raise TypeError("comparison requires FixedDecimal")
        scale = max(self.scale, other.scale)
        return (
            self.coefficient * (10 ** (scale - self.scale)),
            other.coefficient * (10 ** (scale - other.scale)),
        )

    def add(self, other: "FixedDecimal") -> "FixedDecimal":
        left, right = self._aligned(other)
        return FixedDecimal(left + right, max(self.scale, other.scale)).canonical()

    def subtract(self, other: "FixedDecimal") -> "FixedDecimal":
        left, right = self._aligned(other)
        return FixedDecimal(left - right, max(self.scale, other.scale)).canonical()

    def __lt__(self, other: "FixedDecimal") -> bool:
        left, right = self._aligned(other)
        return left < right

    def __str__(self) -> str:
        key = (self.coefficient, self.scale)
        cached = _STR_CACHE.get(key)
        if cached is not None:
            return cached
        sign = "-" if self.coefficient < 0 else ""
        digits = str(abs(self.coefficient))
        if self.scale == 0:
            value = sign + digits
        else:
            digits = digits.rjust(self.scale + 1, "0")
            value = f"{sign}{digits[:-self.scale]}.{digits[-self.scale:]}"
        if len(_STR_CACHE) >= _STR_CACHE_CAP:
            _STR_CACHE.clear()
        _STR_CACHE[key] = value
        return value
