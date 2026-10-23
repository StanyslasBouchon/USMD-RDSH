"""Live capture: dissectors, display filters, the ring, ``show capture`` and the web API."""

import asyncio

import pytest

from usmd_rdsh.cli.runtime import RUNTIME
from usmd_rdsh.node.capture import CAPTURE, FilterError, PacketCapture, compile_filter
from usmd_rdsh.node.crypto import AgreementKey, SigningKey
from usmd_rdsh.node.dissect import dissect_ncp, dissect_ncp_fragment, dissect_nndp, dissect_sp
from usmd_rdsh.node.ncp.codec import Command, Message, MessageType, error_body
from usmd_rdsh.node.ncp.transport import seal_message
from usmd_rdsh.node.nndp import HereIAm, VectorEntry
from usmd_rdsh.node.sp import handshake as hs
from usmd_rdsh.node.sp.session import Payload
from usmd_rdsh.node.states import State
from usmd_rdsh.node.wire import Writer, now_ms

from tests.test_cli import _factory, _router, _run  # noqa: F401  pylint: disable=unused-import

NODE_ID = "01JAB7R9F2W5H1N3S8D0Q4K6ME"


def _hia(**changes) -> bytes:
    stamp = now_ms()
    hia = HereIAm(NODE_ID, stamp + 15000, int(State.ACTIVE), stamp, bytes(32),
                  hosted=[0x00A15D68], vector=[VectorEntry(0x00A10001, 120, 1)])
    for name, value in changes.items():
        setattr(hia, name, value)
    return hia.sign(SigningKey.generate())


def _capture_of(*frames) -> PacketCapture:
    capture = PacketCapture(capacity=100)
    for protocol, direction, src, dst, data, (info, dissection), status in frames:
        capture.record(protocol, direction, src, dst, data, info, dissection, status=status)
    return capture


def _numbers(capture: PacketCapture, text: str) -> list[int]:
    return [p.number for p in capture.packets(flt=compile_filter(text))]


def test_nndp_dissector_names_every_field():
    data = _hia()
    info, dissection = dissect_nndp(data)
    assert info.startswith(f"HIA {NODE_ID} ACTIVE, 1 hosted, 1 vector, I=15 s")
    values = {name: [shown for _, shown, _ in v] for name, v in dissection.fields.items()}
    assert values["nndp.node_id"] == [NODE_ID]
    assert values["nndp.hosted"] == ["0a1.5d68"]
    assert values["nndp.vector.distance"] == ["120"]
    assert "malformed" not in dissection.fields
    # The node identifier is located in the frame: key + signature + header + length.
    node = next(n for n in dissection.tree[0]["c"] if n["f"] == "nndp.node_id")
    assert (node["o"], node["n"]) == (32 + 64 + 9 + 2, 26)
    assert data[node["o"]:node["o"] + 26].decode() == NODE_ID


def test_truncated_frame_is_marked_malformed():
    _, dissection = dissect_nndp(_hia()[:120])
    assert "malformed" in dissection.fields


def test_ncp_message_dissected_after_decryption():
    key = SigningKey.generate()
    body = Writer().u16(int(State.INACTIVE)).bytes()
    plaintext = Message(Command.DECLARE_STATE, MessageType.REQUEST, 7, now_ms(), key.public,
                        body).encode(key, bytes(32))
    info, dissection = dissect_ncp(Command.DECLARE_STATE, plaintext)
    assert info.startswith("DECLARE_STATE Request id=7 INACTIVE")
    assert dissection.buffers[0][1] == plaintext

    error = Message(Command.GET_STATUS, MessageType.ERROR, 7, now_ms(), key.public,
                    error_body(0x0001, "who are you")).encode(key, bytes(32))
    info, _ = dissect_ncp(Command.GET_STATUS, error)
    assert "0x0001 NOT_AUTHORISED who are you" in info

    datagrams, _ = seal_message(Command.GET_STATUS, plaintext, AgreementKey.generate().public)
    info, dissection = dissect_ncp_fragment(datagrams[0])
    assert info == "GET_STATUS fragment 1/1 (encrypted)"


def test_sp_handshake_and_data_frames():
    initiation, _ = hs.build_initiation(SigningKey.generate(), bytes(32),
                                        AgreementKey.generate().public, now_ms(), index=0x1234)
    info, _ = dissect_sp(initiation)
    assert info == "Handshake Initiation index_I=0x00001234"
    frame = bytes.fromhex("d5c1010003") + (12 + 40).to_bytes(4, "big") + bytes(12 + 40)
    info, dissection = dissect_sp(frame, Payload(keepalive=True))
    assert info.endswith("Keepalive")
    assert dissection.fields["sp.keepalive"][0][0] is True


def test_display_filters_follow_wireshark():
    key = SigningKey.generate()
    error = Message(Command.GET_STATUS, MessageType.ERROR, 1, now_ms(), key.public,
                    error_body(0x0005)).encode(key, bytes(32))
    capture = _capture_of(
        ("NNDP", "in", "127.0.0.2:5221", "127.0.0.1:5222", _hia(), dissect_nndp(_hia()), "ok"),
        ("NNDP", "out", "127.0.0.1:5221", "127.0.0.3:5222", b"x", dissect_nndp(b"x"),
         "malformed"),
        ("NCP", "in", "127.0.0.3:9992", "127.0.0.1:9992", b"",
         dissect_ncp(Command.GET_STATUS, error), "ok"),
    )
    assert _numbers(capture, "nndp") == [1, 2]
    assert _numbers(capture, "nndp && ip.src == 127.0.0.2") == [1]
    assert _numbers(capture, "ip.addr == 127.0.0.0/30 and !ncp") == [1, 2]
    assert _numbers(capture, "nndp.state == ACTIVE") == [1]
    assert _numbers(capture, "nndp.state == 0x2000") == [1]
    assert _numbers(capture, "ncp.type == ERROR && ncp.error.code == UNKNOWN_KEY") == [3]
    assert _numbers(capture, "ncp.command eq GET_STATUS") == [3]
    assert _numbers(capture, "frame.status != ok || udp.port == 9992") == [2, 3]
    assert _numbers(capture, "nndp.node_id contains \"jab7\"") == [1]
    assert _numbers(capture, "nndp.node_id matches \"^01J.*ME$\"") == [1]
    assert _numbers(capture, "frame.len > 100") == [1]
    assert _numbers(capture, f'"{NODE_ID[:8]}"') == [1]
    assert _numbers(capture, "(nndp || ncp) && frame.dir == out") == [2]
    assert compile_filter("  ") is None
    for bad in ("nndp &&", "nope.field == 1", "ip.src ==", "(nndp", "ip.addr == 1.2.3/99",
                'nndp.node_id ~ "("'):
        with pytest.raises(FilterError):
            compile_filter(bad)


def test_ring_is_bounded_and_wakes_waiters():
    capture = PacketCapture(capacity=16)

    async def scenario():
        waiter = asyncio.create_task(capture.wait(0, 5))
        await asyncio.sleep(0)
        info, dissection = dissect_nndp(_hia())
        for _ in range(20):
            capture.record("NNDP", "in", "a:1", "b:2", b"", info, dissection)
        await asyncio.wait_for(waiter, 1)

    asyncio.run(scenario())
    assert capture.held() == 16 and capture.last_number == 20
    assert [p.number for p in capture.packets(since=18)] == [19, 20]
    capture.protocols = {"NCP"}
    assert capture.record("NNDP", "in", "a:1", "b:2", b"", "x", dissect_nndp(b"")[1]) is None


def test_show_capture_and_web_api(factory):
    CAPTURE.clear()
    CAPTURE.enabled, CAPTURE.protocols = True, set(CAPTURE.PROTOCOLS)
    info, dissection = dissect_nndp(_hia())
    number = CAPTURE.record("NNDP", "in", "127.0.0.2:5221", "127.0.0.1:5222", _hia(), info,
                            dissection).number
    out = _run(factory, 'show capture filter="nndp && ip.src == 127.0.0.2"',
               f"show capture detail={number}", 'show capture filter="nndp &&"',
               "show capture fields")
    assert f"HIA {NODE_ID}" in out
    assert f"Node ID: {NODE_ID}" in out and "0000  " in out
    assert "invalid filter" in out
    assert "nndp.vector.hops" in out

    admin = {"Authorization": "Bearer " + RUNTIME.tokens.mint("adm", "admin").plaintext}
    router = _router(factory)
    listed = asyncio.run(router.handle("GET", "/web/capture?filter=nndp&since=0", admin))
    assert [p["number"] for p in listed.body["packets"]] == [number]
    bad = asyncio.run(router.handle("GET", "/web/capture?filter=nndp%20%26%26", admin))
    assert bad.status == 422
    detail = asyncio.run(router.handle("GET", f"/web/capture/{number}", admin))
    assert detail.body["tree"][0]["l"] == f"Frame {number}"
    page = asyncio.run(router.handle("GET", "/static/capture.js", {}))
    assert b"UsmdCapture" in page.payload
    cleared = asyncio.run(router.handle("POST", "/web/capture/clear", admin))
    assert cleared.body["cleared"] == 1 and CAPTURE.held() == 0
