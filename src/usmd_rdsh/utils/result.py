"""Result type implementation for handling success and error cases.

This module provides a generic Result type that can be used to handle operations
that might fail, similar to Rust's Result type. It helps in explicit error handling
and provides a clean way to chain operations that might fail.

Examples:
    # Basic usage of Result:
    >>> def divide(a: int, b: int) -> Result[float, str]:
    ...     if b == 0:
    ...         return Result.Err("Division by zero")
    ...     return Result.Ok(a / b)
    ...
    >>> result = divide(10, 2)
    >>> if result.is_ok():
    ...     print(result.unwrap())  # Prints: 5.0
    >>> result = divide(10, 0)
    >>> if result.is_err():
    ...     print(result.unwrap_err())  # Prints: "Division by zero"

    # Using the error collection feature:
    >>> Result.hide()  # Start collecting errors
    >>> divide(10, 2)  # Success operation
    >>> divide(10, 0)  # Failed operation
    >>> final_result = Result.reveal()
    >>> if final_result.is_err():
    ...     print("An error occurred:", final_result.unwrap_err())

    # Aggregating multiple results:
    >>> results = [divide(10, 2), divide(8, 4), divide(6, 2)]
    >>> combined = Result.all(results)
    >>> if combined.is_ok():
    ...     print("All divisions succeeded:", combined.unwrap())
"""

from typing import Any, Generic, TypeVar, Union, cast

T = TypeVar("T")
E = TypeVar("E")


class _ResultCollector:
    """Internal class to manage result collection state without using global statements.

    Attributes:
        hidden_results (list[Result[Any, Any]]): Internal list that collects
            all Result instances when hiding is active
        is_hiding (bool): Flag indicating if result collection is active
    """

    def __init__(self) -> None:
        self.hidden_results: list["Result[Any, Any]"] = []
        self.is_hiding: bool = False

    def start(self) -> None:
        """Start collecting results."""
        self.is_hiding = True
        self.hidden_results = []

    def stop(self) -> list["Result[Any, Any]"]:
        """Stop collecting and return collected results."""
        self.is_hiding = False
        results = self.hidden_results.copy()
        self.hidden_results = []
        return results


_collector = _ResultCollector()


class Result(Generic[T, E]):
    """A generic Result type that represents either a success value of type T
        or an error value of type E.

    This class provides a way to handle operations that might fail, inspired by Rust's
        Result type.
    It includes features for error collection and result aggregation.

    Type Parameters:
        T: The type of the success value
        E: The type of the error value

    Note:
        Result collection state is managed internally by a _ResultCollector instance.

    Example:
        >>> def parse_int(s: str) -> Result[int, str]:
        ...     try:
        ...         return Result.Ok(int(s))
        ...     except ValueError:
        ...         return Result.Err(f"Could not parse '{s}' as integer")
        ...
        >>> result = parse_int("123")
        >>> if result.is_ok():
        ...     value = result.unwrap()  # value = 123
    """

    def __init__(self, value: Union[T, E], is_ok: bool):
        """Initialize a Result instance.

        Args:
            value: The success or error value to store
            is_ok: True if this is a success result, False if it's an error
        """
        self.value: Union[T, E] = value
        self._is_ok = is_ok
        if _collector.is_hiding and isinstance(self, Result):
            _collector.hidden_results.append(self)

    @classmethod
    def hide(cls) -> None:
        """Start collecting all Result instances silently.

        This method enables error collection mode where all Result instances
        are tracked internally until reveal() is called.

        Example:
            >>> Result.hide()
            >>> operation1()  # Returns Result
            >>> operation2()  # Returns Result
            >>> final_result = Result.reveal()
        """
        _collector.start()

    @classmethod
    def reveal(cls) -> "Result[None, E]":
        """Check all collected results and return the final result.

        Returns:
            Result[None, E]: Ok(None) if all collected results were successful,
                           or Err(error) with the first encountered error.

        Example:
            >>> Result.hide()
            >>> operation1()
            >>> operation2()
            >>> result = Result.reveal()
            >>> if result.is_err():
            ...     print("An error occurred:", result.unwrap_err())
        """
        results = _collector.stop()

        for result in results:
            if result.is_err():
                return Result.Err(result.unwrap_err())
        return Result.Ok(None)

    @classmethod
    def Ok(cls, value: T) -> "Result[T, E]":  # pylint: disable=invalid-name
        """Create a success Result with the given value.

        Args:
            value: The success value to store

        Returns:
            A new Result instance containing the success value

        Example:
            >>> result = Result.Ok(42)
            >>> assert result.is_ok()
            >>> assert result.unwrap() == 42
        """
        return cls(value, True)

    @classmethod
    def Err(cls, value: E) -> "Result[T, E]":  # pylint: disable=invalid-name
        """Create an error Result with the given error value.

        Args:
            value: The error value to store

        Returns:
            A new Result instance containing the error value

        Example:
            >>> result = Result.Err("error message")
            >>> assert result.is_err()
            >>> assert result.unwrap_err() == "error message"
        """
        return cls(value, False)

    def is_ok(self) -> bool:
        """Check if this Result contains a success value.

        Returns:
            bool: True if this is a success result, False otherwise
        """
        return self._is_ok

    def is_err(self) -> bool:
        """Check if this Result contains an error value.

        Returns:
            bool: True if this is an error result, False otherwise
        """
        return not self._is_ok

    def unwrap(self) -> T:
        """Extract the success value from this Result.

        Returns:
            T: The success value

        Raises:
            ValueError: If this is an error result

        Example:
            >>> result = Result.Ok(42)
            >>> value = result.unwrap()  # value = 42
            >>> error_result = Result.Err("error")
            >>> error_result.unwrap()  # Raises ValueError
        """
        if self._is_ok:
            return cast(T, self.value)
        raise ValueError(f"Result is an error: {self.value}")

    def unwrap_err(self) -> E:
        """Extract the error value from this Result.

        Returns:
            E: The error value

        Raises:
            ValueError: If this is a success result

        Example:
            >>> result = Result.Err("error message")
            >>> error = result.unwrap_err()  # error = "error message"
            >>> ok_result = Result.Ok(42)
            >>> ok_result.unwrap_err()  # Raises ValueError
        """
        if not self._is_ok:
            return cast(E, self.value)
        raise ValueError(f"Result is an ok: {self.value}")

    @staticmethod
    def all(results: list["Result[Any, E]"]) -> "Result[list[Any], E]":
        """Aggregate multiple Results into a single Result.

        Args:
            results: A list of Result instances to aggregate

        Returns:
            Result[list[Any], E]: A success Result containing a list of all
                                success values if all Results were successful,
                                or the first encountered error Result.

        Example:
            >>> results = [Result.Ok(1), Result.Ok(2), Result.Ok(3)]
            >>> combined = Result.all(results)
            >>> assert combined.unwrap() == [1, 2, 3]
            >>>
            >>> results = [Result.Ok(1), Result.Err("error"), Result.Ok(3)]
            >>> combined = Result.all(results)
            >>> assert combined.unwrap_err() == "error"
        """
        for result in results:
            if result.is_err():
                return Result.Err(result.unwrap_err())
        return Result.Ok([r.unwrap() for r in results])

    def __str__(self) -> str:
        """Convert the Result instance to its string representation.

        Returns a string in the format "Ok(value)" for success results
        or "Err(error)" for error results.

        Returns:
            str: String representation of the Result

        Examples:
            >>> result = Result.Ok(42)
            >>> str(result)  # Returns: "Ok(42)"

            >>> error = Result.Err("not found")
            >>> str(error)  # Returns: "Err(not found)"

            >>> complex_result = Result.Ok({"key": "value"})
            >>> str(complex_result)  # Returns: 'Ok({"key": "value"})'
        """
        if self.is_ok():
            return f"Ok({self.unwrap()})"
        return f"Err({self.unwrap_err()})"
