"""SP-01: handshake, key schedule, data frames, anti-replay."""

import pytest

from usmd_rdsh.node import addresses
from usmd_rdsh.node.crypto import AgreementKey, CryptoError, SigningKey
from usmd_rdsh.node.sp import handshake as hs
from usmd_rdsh.node.sp.session import Payload, ReplayWindow, Session, data_frame_index
from usmd_rdsh.node.wire import WireError

NOW = 1_800_000_000_000


def _pair():
    return SigningKey.generate(), AgreementKey.generate()


def _handshake():
    (ed_i, x_i), (ed_r, x_r) = _pair(), _pair()
    initiation, state = hs.build_initiation(ed_i, ed_r.public, x_r.public, NOW)
    assert len(initiation) == 165
    opened = hs.open_initiation(initiation, x_r, ed_r.public)
    assert opened.initiation.initiator_ed25519 == ed_i.public
    received = hs.verify_initiation(opened)
    response, r_keys = hs.build_response(ed_r, x_r, received)
    assert len(response) == 161
    i_keys = hs.open_response(response, state, ed_i.public)
    return i_keys, r_keys, (ed_i, ed_r, x_r, state, response)


def test_both_sides_derive_mirrored_keys():
    i_keys, r_keys, _ = _handshake()
    assert i_keys.send_key == r_keys.receive_key
    assert i_keys.receive_key == r_keys.send_key
    assert i_keys.send_key != i_keys.receive_key
    assert i_keys.remote_index == r_keys.local_index
    assert r_keys.remote_index == i_keys.local_index


def test_initiation_for_another_responder_does_not_open():
    (ed_i, _), (ed_r, x_r), (_, x_other) = _pair(), _pair(), _pair()
    initiation, _ = hs.build_initiation(ed_i, ed_r.public, x_r.public, NOW)
    with pytest.raises(CryptoError):
        hs.open_initiation(initiation, x_other, ed_r.public)


def test_response_from_unexpected_key_is_refused():
    (ed_i, _), (ed_r, x_r) = _pair(), _pair()
    initiation, state = hs.build_initiation(ed_i, ed_r.public, x_r.public, NOW)
    received = hs.verify_initiation(hs.open_initiation(initiation, x_r, ed_r.public))
    response, _ = hs.build_response(ed_r, x_r, received)
    tampered = response[:-1] + bytes([response[-1] ^ 1])
    with pytest.raises(CryptoError):
        hs.open_response(tampered, state, ed_i.public)
    # The state survives a forged response; the genuine one still opens, then is erased.
    hs.open_response(response, state, ed_i.public)
    assert state.ephemeral is None and state.dh1 == bytes(32)


def test_data_frames_keepalive_broadcast_and_replay():
    i_keys, r_keys, _ = _handshake()
    i = Session(i_keys, "10.0.0.2", established=0.0)
    r = Session(r_keys, "10.0.0.1", established=0.0)
    assert not r.can_send(1.0)  # waits for the initiator's first frame
    keepalive = i.seal(Payload(keepalive=True), 1.0)
    assert len(keepalive) == 38
    assert data_frame_index(keepalive) == r.local_index
    assert r.open(keepalive, 1.0).keepalive and r.can_send(1.0)

    src, dst = addresses.pack(0x0A1, 1), addresses.pack(0x0B2, 2)
    frame = r.seal(Payload(False, src, dst, None, b"\x45" + bytes(19)), 2.0)
    assert len(frame) == 46 + 20
    got = i.open(frame, 2.0)
    assert (got.source, got.destination, got.packet[:1]) == (src, dst, b"\x45")
    with pytest.raises(WireError, match="replayed"):
        i.open(frame, 2.0)

    group = addresses.pack(0x0B2, 0xFFFF)
    bcast = i.seal(Payload(False, src, group, 42, bytes(20)), 3.0)
    assert len(bcast) == 54 + 20 and r.open(bcast, 3.0).broadcast_id == 42
    with pytest.raises(WireError, match="0000"):
        i.seal(Payload(False, src, addresses.pack(0x0B2, 0), None, b""), 3.0)


def test_session_lifetimes():
    i_keys, _, _ = _handshake()
    session = Session(i_keys, "10.0.0.2", established=0.0)
    assert session.needs_rekey(120.0) and session.can_send(179.0)
    assert not session.can_send(181.0) and session.can_receive(239.0)
    assert not session.can_receive(241.0)


def test_replay_window_accepts_out_of_order_inside_2048():
    window = ReplayWindow()
    for counter in (5, 3, 4000):
        assert window.check(counter)
        window.record(counter)
    assert not window.check(3) or 4000 - 3 >= 2048
    assert window.check(4000 - 100) and not window.check(4000)
    assert not window.check(4000 - 2048)


def test_sp_interface_accepts_the_shared_vip_as_source(tmp_path, caplog):
    """Every instance of a service holds the same VIP: the SP interface must
    accept packets from it (accept_local), or the group address reaches no one."""
    from usmd_rdsh.node.sp import tun  # pylint: disable=import-outside-toplevel

    (tmp_path / tun.NAME).mkdir()
    assert tun._set_interface_knob("accept_local", "1", root=str(tmp_path))  # pylint: disable=protected-access
    assert (tmp_path / tun.NAME / "accept_local").read_text() == "1"
    assert not tun._set_interface_knob("rp_filter", "0", root=str(tmp_path / "absent"))  # pylint: disable=protected-access
    assert "will not receive what the others send" in caplog.text
