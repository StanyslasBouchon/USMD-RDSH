"""Tests for the NCP TCP client (NcpClient)."""

import asyncio
import struct
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from usmd.ncp.client.tcp import NcpClient
from usmd.ncp.protocol.frame import NcpCommandId, NcpFrame
from usmd.ncp.protocol.versions import NcpVersion
from usmd.utils.errors import ErrorKind


def _make_response_bytes(command_id: NcpCommandId, payload: bytes = b"") -> bytes:
    """Build a raw NCP response frame."""
    version = NcpVersion(1, 0, 0, 0)
    frame = NcpFrame(version=version, command_id=command_id, payload=payload)
    return frame.to_bytes()


class TestNcpClient:
    def test_init(self):
        client = NcpClient("10.0.0.1", port=5626, timeout=5.0)
        assert client.address == "10.0.0.1"
        assert client.port == 5626
        assert client.timeout == 5.0

    def test_init_defaults(self):
        client = NcpClient("10.0.0.1")
        assert client.port == 5626
        assert client.timeout == 5.0

    @pytest.mark.asyncio
    async def test_send_returns_response_frame(self):
        """A successful send returns the parsed response frame."""
        resp_bytes = _make_response_bytes(NcpCommandId.GET_STATUS, b"payload_here")

        mock_reader = AsyncMock()
        mock_writer = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.wait_closed = AsyncMock()

        # readexactly(9) → header, readexactly(len) → payload
        header = resp_bytes[:9]
        payload = resp_bytes[9:]
        mock_reader.readexactly = AsyncMock(side_effect=[header, payload])

        with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
            client = NcpClient("10.0.0.1")
            result = await client.send(NcpCommandId.GET_STATUS, b"")

        assert result.is_ok()
        frame = result.unwrap()
        assert frame.command_id == NcpCommandId.GET_STATUS
        assert frame.payload == b"payload_here"

    @pytest.mark.asyncio
    async def test_send_empty_payload_response(self):
        """Response with zero-length payload should work."""
        resp_bytes = _make_response_bytes(NcpCommandId.SEND_USD_PROPERTIES, b"")

        mock_reader = AsyncMock()
        mock_writer = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.wait_closed = AsyncMock()

        header = resp_bytes[:9]
        # payload_len is 0, so readexactly is only called once (header)
        mock_reader.readexactly = AsyncMock(return_value=header)

        with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
            client = NcpClient("10.0.0.1")
            result = await client.send(NcpCommandId.SEND_USD_PROPERTIES, b"")

        assert result.is_ok()
        assert result.unwrap().payload == b""

    @pytest.mark.asyncio
    async def test_send_connection_refused(self):
        """Connection failure should return an Err result."""
        with patch(
            "asyncio.open_connection", side_effect=ConnectionRefusedError("refused")
        ):
            client = NcpClient("10.0.0.1")
            result = await client.send(NcpCommandId.GET_STATUS, b"")

        assert result.is_err()
        err = result.unwrap_err()
        assert err.kind == ErrorKind.CONNECTION_ERROR

    @pytest.mark.asyncio
    async def test_send_timeout(self):
        """Connection timeout should return an Err result."""
        with patch(
            "asyncio.open_connection",
            new=AsyncMock(side_effect=asyncio.TimeoutError()),
        ):
            client = NcpClient("10.0.0.1", timeout=0.001)
            result = await client.send(NcpCommandId.GET_STATUS, b"")

        assert result.is_err()
        assert result.unwrap_err().kind == ErrorKind.CONNECTION_ERROR

    @pytest.mark.asyncio
    async def test_send_incomplete_header(self):
        """IncompleteReadError on header should return Err."""
        mock_reader = AsyncMock()
        mock_writer = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.wait_closed = AsyncMock()
        mock_reader.readexactly = AsyncMock(
            side_effect=asyncio.IncompleteReadError(b"", 9)
        )

        with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
            client = NcpClient("10.0.0.1")
            result = await client.send(NcpCommandId.GET_STATUS, b"")

        assert result.is_err()
        assert result.unwrap_err().kind == ErrorKind.CONNECTION_ERROR

    @pytest.mark.asyncio
    async def test_send_incomplete_payload(self):
        """IncompleteReadError on payload should return Err."""
        resp_bytes = _make_response_bytes(NcpCommandId.GET_STATUS, b"data")
        header = resp_bytes[:9]

        mock_reader = AsyncMock()
        mock_writer = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.wait_closed = AsyncMock()
        mock_reader.readexactly = AsyncMock(
            side_effect=[
                header,
                asyncio.IncompleteReadError(b"da", 4),
            ]
        )

        with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
            client = NcpClient("10.0.0.1")
            result = await client.send(NcpCommandId.GET_STATUS, b"")

        assert result.is_err()
        assert result.unwrap_err().kind == ErrorKind.CONNECTION_ERROR
