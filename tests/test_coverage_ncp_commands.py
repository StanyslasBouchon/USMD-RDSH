"""Coverage tests for NCP command protocol classes.

Covers:
- announce_promotion.py  (AnnouncePromotionRequest/Response)
- request_vote.py        (RequestVoteRequest/Response)
- get_nqt.py             (GetNqtRequest/Response)
- inform_reference_node.py (InformReferenceNodeRequest)
- request_snapshot.py    (RequestSnapshotRequest/Response)
- check_distance.py      (CheckDistanceRequest/Response)
- get_status.py          (GetStatusRequest/Response)
- revoke_endorsement.py  (RevokeEndorsementRequest/Response)
- send_usd_properties.py (SendUsdPropertiesRequest/Response)
"""

from __future__ import annotations

import json
import struct

import pytest

from usmd.ncp.protocol.commands.announce_promotion import (
    AnnouncePromotionRequest,
    AnnouncePromotionResponse,
)
from usmd.ncp.protocol.commands.request_vote import (
    RequestVoteRequest,
    RequestVoteResponse,
)
from usmd.ncp.protocol.commands.get_nqt import GetNqtRequest, GetNqtResponse
from usmd.ncp.protocol.commands.inform_reference_node import InformReferenceNodeRequest
from usmd.ncp.protocol.commands.request_snapshot import (
    RequestSnapshotRequest,
    RequestSnapshotResponse,
)
from usmd.ncp.protocol.commands.check_distance import (
    CheckDistanceRequest,
    CheckDistanceResponse,
)


# ===========================================================================
# announce_promotion.py
# ===========================================================================

KEY = b"k" * 32


class TestAnnouncePromotionRequest:
    def test_to_payload_json(self):
        req = AnnouncePromotionRequest(
            epoch=5, role="usd_operator", pub_key=KEY, address="10.0.0.1"
        )
        data = json.loads(req.to_payload())
        assert data["epoch"] == 5
        assert data["role"] == "usd_operator"
        assert data["pub_key_hex"] == KEY.hex()
        assert data["address"] == "10.0.0.1"

    def test_from_payload_json_roundtrip(self):
        req = AnnouncePromotionRequest(1, "node_operator", KEY, "1.2.3.4")
        parsed = AnnouncePromotionRequest.from_payload(req.to_payload())
        assert parsed.is_ok()
        obj = parsed.unwrap()
        assert obj.epoch == 1
        assert obj.role == "node_operator"
        assert obj.pub_key == KEY
        assert obj.address == "1.2.3.4"

    def test_from_payload_legacy_binary(self):
        epoch_bytes = struct.pack("!I", 7)
        address_bytes = b"10.0.0.7"
        legacy = epoch_bytes + KEY + address_bytes
        parsed = AnnouncePromotionRequest.from_payload(legacy)
        assert parsed.is_ok()
        obj = parsed.unwrap()
        assert obj.epoch == 7
        assert obj.pub_key == KEY
        assert obj.role == "node_operator"  # defaults to node_operator for legacy

    def test_from_payload_too_short(self):
        r = AnnouncePromotionRequest.from_payload(b"\x00" * 5)
        assert r.is_err()

    def test_from_payload_invalid_hex_in_json(self):
        payload = json.dumps({
            "epoch": 1,
            "role": "node_operator",
            "pub_key_hex": "ZZZZ",  # invalid hex
            "address": "1.2.3.4",
        }).encode()
        r = AnnouncePromotionRequest.from_payload(payload)
        assert r.is_ok()
        assert r.unwrap().pub_key == b""


class TestAnnouncePromotionResponse:
    def test_to_payload_empty(self):
        assert AnnouncePromotionResponse().to_payload() == b""

    def test_from_payload_always_ok(self):
        r = AnnouncePromotionResponse.from_payload(b"anything")
        assert r.is_ok()


# ===========================================================================
# request_vote.py
# ===========================================================================


class TestRequestVoteRequest:
    def test_to_payload_json(self):
        req = RequestVoteRequest(epoch=3, role="usd_operator",
                                 candidate_address="192.168.1.1")
        data = json.loads(req.to_payload())
        assert data["epoch"] == 3
        assert data["role"] == "usd_operator"
        assert data["candidate_address"] == "192.168.1.1"

    def test_from_payload_json_roundtrip(self):
        req = RequestVoteRequest(epoch=1, candidate_address="1.2.3.4",
                                 role="ucd_operator")
        parsed = RequestVoteRequest.from_payload(req.to_payload())
        assert parsed.is_ok()
        obj = parsed.unwrap()
        assert obj.epoch == 1
        assert obj.role == "ucd_operator"
        assert obj.candidate_address == "1.2.3.4"

    def test_from_payload_legacy_binary(self):
        epoch_bytes = struct.pack("!I", 2)
        address_bytes = b"10.0.0.2"
        legacy = epoch_bytes + address_bytes
        parsed = RequestVoteRequest.from_payload(legacy)
        assert parsed.is_ok()
        obj = parsed.unwrap()
        assert obj.epoch == 2
        assert obj.role == "node_operator"

    def test_from_payload_too_short(self):
        r = RequestVoteRequest.from_payload(b"\x00" * 3)
        assert r.is_err()

    def test_default_role(self):
        req = RequestVoteRequest(epoch=1, candidate_address="10.0.0.1")
        assert req.role == "node_operator"


class TestRequestVoteResponse:
    def test_yes_payload(self):
        assert RequestVoteResponse(granted=True).to_payload() == b"\x01"

    def test_no_payload(self):
        assert RequestVoteResponse(granted=False).to_payload() == b"\x00"

    def test_from_payload_yes(self):
        r = RequestVoteResponse.from_payload(b"\x01")
        assert r.is_ok()
        assert r.unwrap().granted is True

    def test_from_payload_no(self):
        r = RequestVoteResponse.from_payload(b"\x00")
        assert r.is_ok()
        assert r.unwrap().granted is False

    def test_from_payload_empty_err(self):
        r = RequestVoteResponse.from_payload(b"")
        assert r.is_err()


# ===========================================================================
# get_nqt.py
# ===========================================================================


class TestGetNqtRequest:
    def test_to_payload_empty(self):
        assert GetNqtRequest().to_payload() == b""

    def test_from_payload_always_ok(self):
        r = GetNqtRequest.from_payload(b"ignored")
        assert r.is_ok()


class TestGetNqtResponse:
    def test_empty_payload(self):
        assert GetNqtResponse(entries=[]).to_payload() == b"[]"

    def test_roundtrip(self):
        entries = [{"epoch": 1, "address": "10.0.0.1"}]
        resp = GetNqtResponse(entries=entries)
        parsed = GetNqtResponse.from_payload(resp.to_payload())
        assert parsed.is_ok()
        assert parsed.unwrap().entries[0]["epoch"] == 1

    def test_from_payload_empty_bytes(self):
        r = GetNqtResponse.from_payload(b"")
        assert r.is_ok()
        assert r.unwrap().entries == []

    def test_from_payload_invalid_json(self):
        r = GetNqtResponse.from_payload(b"not-json")
        assert r.is_err()

    def test_from_payload_non_array_json(self):
        r = GetNqtResponse.from_payload(b'{"key": "value"}')
        assert r.is_err()


# ===========================================================================
# inform_reference_node.py
# ===========================================================================


class TestInformReferenceNodeRequest:
    def test_roundtrip(self):
        req = InformReferenceNodeRequest(
            sender_name=1710000001,
            sender_address="10.0.0.2",
            reference_names=[1710000003, 1710000004],
        )
        parsed = InformReferenceNodeRequest.from_payload(req.to_payload())
        assert parsed.is_ok()
        obj = parsed.unwrap()
        assert obj.sender_name == 1710000001
        assert obj.sender_address == "10.0.0.2"
        assert obj.reference_names == [1710000003, 1710000004]

    def test_default_reference_names(self):
        req = InformReferenceNodeRequest(sender_name=1, sender_address="10.0.0.1")
        assert req.reference_names == []

    def test_from_payload_invalid(self):
        r = InformReferenceNodeRequest.from_payload(b"not-json")
        assert r.is_err()


# ===========================================================================
# request_snapshot.py
# ===========================================================================


class TestRequestSnapshotRequest:
    def test_to_payload_empty(self):
        assert RequestSnapshotRequest().to_payload() == b""

    def test_from_payload_always_ok(self):
        r = RequestSnapshotRequest.from_payload(b"")
        assert r.is_ok()


class TestRequestSnapshotResponse:
    def test_roundtrip(self):
        snap = {"node": {"address": "10.0.0.1"}, "resources": {}}
        resp = RequestSnapshotResponse(snapshot=snap)
        parsed = RequestSnapshotResponse.from_payload(resp.to_payload())
        assert parsed.is_ok()
        obj = parsed.unwrap()
        assert obj.snapshot["node"]["address"] == "10.0.0.1"

    def test_from_payload_invalid_json(self):
        r = RequestSnapshotResponse.from_payload(b"not-json")
        assert r.is_err()

    def test_from_payload_empty(self):
        r = RequestSnapshotResponse.from_payload(b"")
        assert r.is_err()


# ===========================================================================
# check_distance.py
# ===========================================================================


class TestCheckDistanceRequest:
    def test_roundtrip(self):
        req = CheckDistanceRequest(sent_at_ms=1_710_000_000_000)
        parsed = CheckDistanceRequest.from_payload(req.to_payload())
        assert parsed.is_ok()
        obj = parsed.unwrap()
        assert obj.sent_at_ms == 1_710_000_000_000

    def test_payload_length(self):
        req = CheckDistanceRequest(sent_at_ms=1000)
        assert len(req.to_payload()) == 8

    def test_from_payload_too_short(self):
        r = CheckDistanceRequest.from_payload(b"\x00" * 7)
        assert r.is_err()


class TestCheckDistanceResponse:
    def test_roundtrip(self):
        resp = CheckDistanceResponse(distance=1.5)
        parsed = CheckDistanceResponse.from_payload(resp.to_payload())
        assert parsed.is_ok()
        assert abs(parsed.unwrap().distance - 1.5) < 0.001

    def test_payload_length(self):
        resp = CheckDistanceResponse(distance=2.5)
        assert len(resp.to_payload()) == 8

    def test_from_payload_too_short(self):
        r = CheckDistanceResponse.from_payload(b"\x00" * 7)
        assert r.is_err()


# ===========================================================================
# get_status.py
# ===========================================================================


class TestGetStatus:
    def test_request_empty(self):
        from usmd.ncp.protocol.commands.get_status import GetStatusRequest
        req = GetStatusRequest()
        assert req.to_payload() == b""
        assert GetStatusRequest.from_payload(b"").is_ok()

    def test_node_status_reference_load(self):
        from usmd.ncp.protocol.commands.get_status import GetStatusRequest, GetStatusResponse, NodeStatus
        from usmd.node.state import NodeState
        status = NodeStatus(
            ram_percent=0.5,
            cpu_percent=0.8,
            disk_percent=0.3,
            network_percent=0.1,
            service_name="backend",
            state=NodeState.ACTIVE,
        )
        assert status.reference_load() == 0.8

    def test_get_status_response_roundtrip(self):
        from usmd.ncp.protocol.commands.get_status import GetStatusRequest, GetStatusResponse, NodeStatus
        from usmd.node.state import NodeState
        status = NodeStatus(
            ram_percent=0.4,
            cpu_percent=0.3,
            disk_percent=0.2,
            network_percent=0.1,
            service_name=None,
            state=NodeState.ACTIVE,
        )
        resp = GetStatusResponse(status)
        parsed = GetStatusResponse.from_payload(resp.to_payload())
        assert parsed.is_ok()
        obj = parsed.unwrap()
        assert abs(obj.status.cpu_percent - 0.3) < 0.001
        assert obj.status.service_name is None
        assert obj.status.hosting_static == []
        assert obj.status.hosting_dynamic == []

    def test_get_status_hosting_roundtrip(self):
        from usmd.ncp.protocol.commands.get_status import GetStatusResponse, NodeStatus
        from usmd.node.state import NodeState

        status = NodeStatus(
            0.1,
            0.2,
            0.3,
            0.4,
            "x",
            NodeState.ACTIVE,
            hosting_static=["a"],
            hosting_dynamic=["b"],
        )
        raw = GetStatusResponse(status).to_payload()
        parsed = GetStatusResponse.from_payload(raw).unwrap()
        assert parsed.status.hosting_static == ["a"]
        assert parsed.status.hosting_dynamic == ["b"]

    def test_get_status_response_invalid(self):
        from usmd.ncp.protocol.commands.get_status import GetStatusResponse
        r = GetStatusResponse.from_payload(b"not-json")
        assert r.is_err()


# ===========================================================================
# revoke_endorsement.py
# ===========================================================================


class TestRevokeEndorsement:
    def test_request_roundtrip(self):
        from usmd.ncp.protocol.commands.revoke_endorsement import (
            RevokeEndorsementRequest,
            RevokeEndorsementResponse,
        )
        req = RevokeEndorsementRequest(sender_pub_key=b"k" * 32)
        assert len(req.to_payload()) == 32
        parsed = RevokeEndorsementRequest.from_payload(req.to_payload())
        assert parsed.is_ok()
        assert parsed.unwrap().sender_pub_key == b"k" * 32

    def test_request_too_short(self):
        from usmd.ncp.protocol.commands.revoke_endorsement import RevokeEndorsementRequest
        r = RevokeEndorsementRequest.from_payload(b"\x00" * 10)
        assert r.is_err()

    def test_response_empty(self):
        from usmd.ncp.protocol.commands.revoke_endorsement import RevokeEndorsementResponse
        resp = RevokeEndorsementResponse()
        assert resp.to_payload() == b""
        assert RevokeEndorsementResponse.from_payload(b"").is_ok()


# ===========================================================================
# request_approval.py
# ===========================================================================


class TestRequestApproval:
    def test_request_roundtrip(self):
        from usmd.ncp.protocol.commands.request_approval import (
            RequestApprovalRequest,
            RequestApprovalResponse,
        )
        req = RequestApprovalRequest(
            node_name=1710000001,
            ed25519_pub=b"e" * 32,
            x25519_pub=b"x" * 32,
            nonce=b"n" * 16,
            signature=b"s" * 64,
        )
        parsed = RequestApprovalRequest.from_payload(req.to_payload())
        assert parsed.is_ok()
        obj = parsed.unwrap()
        assert obj.node_name == 1710000001

    def test_request_invalid_json(self):
        from usmd.ncp.protocol.commands.request_approval import RequestApprovalRequest
        r = RequestApprovalRequest.from_payload(b"not-json")
        assert r.is_err()


# ===========================================================================
# request_emergency.py
# ===========================================================================


class TestRequestEmergency:
    def test_request_roundtrip(self):
        from usmd.ncp.protocol.commands.request_emergency import (
            RequestEmergencyRequest,
            RequestEmergencyResponse,
        )
        req = RequestEmergencyRequest(already_notified=[1710000001, 1710000002])
        parsed = RequestEmergencyRequest.from_payload(req.to_payload())
        assert parsed.is_ok()
        assert parsed.unwrap().already_notified == [1710000001, 1710000002]

    def test_response_can_help(self):
        from usmd.ncp.protocol.commands.request_emergency import RequestEmergencyResponse
        resp = RequestEmergencyResponse(can_help=True)
        parsed = RequestEmergencyResponse.from_payload(resp.to_payload())
        assert parsed.is_ok()
        assert parsed.unwrap().can_help is True

    def test_response_cannot_help(self):
        from usmd.ncp.protocol.commands.request_emergency import RequestEmergencyResponse
        resp = RequestEmergencyResponse(can_help=False)
        parsed = RequestEmergencyResponse.from_payload(resp.to_payload())
        assert parsed.is_ok()
        assert parsed.unwrap().can_help is False

    def test_request_empty_list(self):
        from usmd.ncp.protocol.commands.request_emergency import RequestEmergencyRequest
        req = RequestEmergencyRequest()
        parsed = RequestEmergencyRequest.from_payload(req.to_payload())
        assert parsed.is_ok()
        assert parsed.unwrap().already_notified == []


# ===========================================================================
# request_help.py
# ===========================================================================


class TestRequestHelp:
    def test_request_roundtrip(self):
        from usmd.ncp.protocol.commands.request_help import RequestHelpRequest, RequestHelpResponse
        req = RequestHelpRequest(already_notified=[1, 2, 3])
        parsed = RequestHelpRequest.from_payload(req.to_payload())
        assert parsed.is_ok()
        assert parsed.unwrap().already_notified == [1, 2, 3]

    def test_response_roundtrip(self):
        from usmd.ncp.protocol.commands.request_help import RequestHelpResponse
        resp = RequestHelpResponse(can_help=False)
        parsed = RequestHelpResponse.from_payload(resp.to_payload())
        assert parsed.is_ok()
        assert parsed.unwrap().can_help is False
