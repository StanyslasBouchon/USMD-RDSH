"""Stream I/O helpers shared across NCP and CTL modules.

Provides small utility functions for closing asyncio StreamWriters
in a safe, consistent way, eliminating duplicated finally-block patterns.

Examples:
    >>> import asyncio, unittest.mock as m
    >>> w = m.MagicMock(spec=asyncio.StreamWriter)
    >>> close_writer(w)
    >>> w.close.assert_called_once()
"""

import asyncio


def close_writer(writer: asyncio.StreamWriter) -> None:
    """Close a StreamWriter, silently ignoring OSError on close.

    Used in CTL handlers where wait_closed() is not needed.

    Args:
        writer: The StreamWriter to close.

    Example:
        >>> import asyncio, unittest.mock as m
        >>> w = m.MagicMock(spec=asyncio.StreamWriter)
        >>> close_writer(w)
        >>> w.close.assert_called_once()
    """
    try:
        writer.close()
    except OSError:
        pass


async def close_stream_writer(writer: asyncio.StreamWriter) -> None:
    """Close an asyncio StreamWriter and wait for the connection to close.

    Used in NCP handlers where wait_closed() is required to fully release
    the underlying socket.

    Args:
        writer: The StreamWriter to close.

    Example:
        >>> import asyncio, unittest.mock as m
        >>> w = m.AsyncMock(spec=asyncio.StreamWriter)
        >>> asyncio.run(close_stream_writer(w))
        >>> w.close.assert_called_once()
    """
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
