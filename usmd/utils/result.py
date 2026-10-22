"""Result type implementation for explicit success/error handling.

This module provides a generic Result type inspired by Rust's Result,
for all USMD-RDSH operations that may succeed or fail.

Examples:
    >>> def divide(a: int, b: int) -> Result[float, str]:
    ...     if b == 0:
    ...         return Result.Err("Division by zero")
    ...     return Result.Ok(a / b)
    ...
    >>> result = divide(10, 2)
    >>> if result.is_ok():
    ...     print(result.unwrap())  # 5.0
    >>> result = divide(10, 0)
    >>> if result.is_err():
    ...     print(result.unwrap_err())  # "Division by zero"
"""

from typing import Any, Generic, TypeVar, Union, cast

T = TypeVar("T")
E = TypeVar("E")


class _ResultCollector:
    """Internal class to collect Result instances during a guarded block.

    Attributes:
        hidden_results: Collected results while hiding is active.
        is_hiding: Whether collection is currently active.
    """

    def __init__(self) -> None:
        self.hidden_results: list["Result[Any, Any]"] = []
        self.is_hiding: bool = False

    def start(self) -> None:
        """Begin collecting results."""
        self.is_hiding = True
        self.hidden_results = []

    def stop(self) -> list["Result[Any, Any]"]:
        """Stop collecting and return all collected results."""
        self.is_hiding = False
        results = self.hidden_results.copy()
        self.hidden_results = []
        return results


_collector = _ResultCollector()


class Result(Generic[T, E]):
    """Generic Result type representing either a success value of type T
    or an error value of type E.

    This pattern follows Rust's Result type, enabling explicit, type-safe
    error propagation throughout USMD-RDSH without exceptions.

    Type Parameters:
        T: The type of the success value.
        E: The type of the error value.

    Examples:
        >>> result = Result.Ok(42)
        >>> result.is_ok()
        True
        >>> result.unwrap()
        42

        >>> error = Result.Err("not found")
        >>> error.is_err()
        True
        >>> error.unwrap_err()
        'not found'
    """

    def __init__(self, value: Union[T, E], is_ok: bool) -> None:
        self.value: Union[T, E] = value
        self._is_ok = is_ok
        if _collector.is_hiding:
            _collector.hidden_results.append(self)

    @classmethod
    def hide(cls) -> None:
        """Start collecting all Result instances silently.

        Use together with reveal() to aggregate errors over multiple operations.

        Example:
            >>> Result.hide()
            >>> op1()
            >>> op2()
            >>> final = Result.reveal()
        """
        _collector.start()

    @classmethod
    def reveal(cls) -> "Result[None, E]":
        """Stop collecting and return the first error, or Ok(None) if all succeeded.

        Returns:
            Result[None, E]: Ok(None) if all collected results were successful,
                             or the first Err encountered.

        Example:
            >>> Result.hide()
            >>> Result.Ok(1)
            >>> Result.Err("oops")
            >>> Result.reveal().is_err()
            True
        """
        results = _collector.stop()
        for result in results:
            if result.is_err():
                return Result.Err(result.unwrap_err())
        return Result.Ok(None)

    @classmethod
    def Ok(cls, value: T) -> "Result[T, E]":
        """Create a success Result.

        Args:
            value: The success value.

        Returns:
            Result containing the success value.

        Example:
            >>> Result.Ok(42).unwrap()
            42
        """
        return cls(value, True)

    @classmethod
    def Err(cls, value: E) -> "Result[T, E]":
        """Create an error Result.

        Args:
            value: The error value.

        Returns:
            Result containing the error value.

        Example:
            >>> Result.Err("oops").unwrap_err()
            'oops'
        """
        return cls(value, False)

    def is_ok(self) -> bool:
        """Return True if this Result contains a success value."""
        return self._is_ok

    def is_err(self) -> bool:
        """Return True if this Result contains an error value."""
        return not self._is_ok

    def unwrap(self) -> T:
        """Extract the success value.

        Raises:
            ValueError: If this is an error Result.

        Example:
            >>> Result.Ok(10).unwrap()
            10
        """
        if self._is_ok:
            return cast(T, self.value)
        raise ValueError(f"Result is an error: {self.value}")

    def unwrap_err(self) -> E:
        """Extract the error value.

        Raises:
            ValueError: If this is a success Result.

        Example:
            >>> Result.Err("boom").unwrap_err()
            'boom'
        """
        if not self._is_ok:
            return cast(E, self.value)
        raise ValueError(f"Result is ok: {self.value}")

    @staticmethod
    def all(results: list["Result[Any, E]"]) -> "Result[list[Any], E]":
        """Aggregate a list of Results into a single Result.

        Returns Ok with all values if every Result succeeded,
        or the first Err encountered.

        Args:
            results: List of Result instances to aggregate.

        Returns:
            Result[list[Any], E]: Ok with all values, or the first error.

        Example:
            >>> Result.all([Result.Ok(1), Result.Ok(2)]).unwrap()
            [1, 2]
            >>> Result.all([Result.Ok(1), Result.Err("e")]).is_err()
            True
        """
        for result in results:
            if result.is_err():
                return Result.Err(result.unwrap_err())
        return Result.Ok([r.unwrap() for r in results])

    def __str__(self) -> str:
        if self.is_ok():
            return f"Ok({self.unwrap()})"
        return f"Err({self.unwrap_err()})"
