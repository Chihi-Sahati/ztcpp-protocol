"""Tests for KNK payload parsing and validation."""

from __future__ import annotations

import base64
import json
import pytest

from app.protocol.knk import NhpKnkParser, KnkParseError


class TestKnkParser:

    def test_parse_valid_payload(self):
        """A valid JSON payload should parse successfully."""
        payload = {
            "version": "1.0",
            "node_id": "agent-001",
            "timestamp": 1735689600,
            "nonce": base64.b64encode(b"\x01" * 24).decode("ascii"),
            "public_key": base64.b64encode(b"\x02" * 32).decode("ascii"),
            "jws": "header.payload.signature",
            "edns_score": 0.15,
            "capabilities": ["soc-analysis"],
        }
        raw = json.dumps(payload).encode("utf-8")
        result = NhpKnkParser.parse(raw)
        assert result.version == "1.0"
        assert result.node_id == "agent-001"
        assert result.edns_score == 0.15

    def test_parse_invalid_json_rejects(self):
        """Invalid JSON should be rejected."""
        with pytest.raises(KnkParseError, match="Invalid JSON"):
            NhpKnkParser.parse(b"not json at all")

    def test_parse_missing_required_field_rejects(self):
        """Missing required fields should be rejected."""
        payload = {"version": "1.0"}
        raw = json.dumps(payload).encode("utf-8")
        with pytest.raises(KnkParseError, match="Schema validation"):
            NhpKnkParser.parse(raw)

    def test_parse_wrong_version_rejects(self):
        """Wrong version should be rejected by schema validation."""
        payload = {
            "version": "2.0",
            "node_id": "agent-001",
            "timestamp": 1735689600,
            "nonce": base64.b64encode(b"\x01" * 24).decode("ascii"),
            "public_key": base64.b64encode(b"\x02" * 32).decode("ascii"),
            "jws": "header.payload.signature",
            "edns_score": 0.15,
            "capabilities": ["soc-analysis"],
        }
        raw = json.dumps(payload).encode("utf-8")
        with pytest.raises(KnkParseError, match="Schema validation"):
            NhpKnkParser.parse(raw)

    @pytest.mark.asyncio
    async def test_validate_nonce_valid(self):
        """A valid nonce with sufficient entropy should pass."""
        payload = {
            "version": "1.0",
            "node_id": "agent-001",
            "timestamp": 1735689600,
            "nonce": base64.b64encode(b"\x01" * 24).decode("ascii"),
            "public_key": base64.b64encode(b"\x02" * 32).decode("ascii"),
            "jws": "header.payload.signature",
            "edns_score": 0.15,
            "capabilities": ["soc-analysis"],
        }
        raw = json.dumps(payload).encode("utf-8")
        parsed = NhpKnkParser.parse(raw)
        await NhpKnkParser.validate_nonce(parsed)  # Should not raise

    @pytest.mark.asyncio
    async def test_validate_nonce_too_short_rejects(self):
        """A nonce string that is too short should be rejected by Pydantic."""
        payload = {
            "version": "1.0",
            "node_id": "agent-001",
            "timestamp": 1735689600,
            "nonce": "short",  # Too short string
            "public_key": base64.b64encode(b"\x02" * 32).decode("ascii"),
            "jws": "header.payload.signature",
            "edns_score": 0.15,
            "capabilities": ["soc-analysis"],
        }
        raw = json.dumps(payload).encode("utf-8")
        with pytest.raises(KnkParseError, match="Schema validation"):
            NhpKnkParser.parse(raw)

    @pytest.mark.asyncio
    async def test_validate_timestamp_current(self):
        """A current timestamp should pass."""
        import time
        payload = {
            "version": "1.0",
            "node_id": "agent-001",
            "timestamp": int(time.time()),
            "nonce": base64.b64encode(b"\x01" * 24).decode("ascii"),
            "public_key": base64.b64encode(b"\x02" * 32).decode("ascii"),
            "jws": "header.payload.signature",
            "edns_score": 0.15,
            "capabilities": ["soc-analysis"],
        }
        raw = json.dumps(payload).encode("utf-8")
        parsed = NhpKnkParser.parse(raw)
        await NhpKnkParser.validate_timestamp(parsed)  # Should not raise

    @pytest.mark.asyncio
    async def test_validate_timestamp_stale_rejects(self):
        """A timestamp that is too old should be rejected."""
        import time
        payload = {
            "version": "1.0",
            "node_id": "agent-001",
            "timestamp": int(time.time()) - 600,  # 10 minutes ago
            "nonce": base64.b64encode(b"\x01" * 24).decode("ascii"),
            "public_key": base64.b64encode(b"\x02" * 32).decode("ascii"),
            "jws": "header.payload.signature",
            "edns_score": 0.15,
            "capabilities": ["soc-analysis"],
        }
        raw = json.dumps(payload).encode("utf-8")
        parsed = NhpKnkParser.parse(raw)
        with pytest.raises(KnkParseError, match="Timestamp drift"):
            await NhpKnkParser.validate_timestamp(parsed)

    @pytest.mark.asyncio
    async def test_validate_capability_pattern(self):
        """Capabilities must match the valid pattern."""
        payload = {
            "version": "1.0",
            "node_id": "agent-001",
            "timestamp": 1735689600,
            "nonce": base64.b64encode(b"\x01" * 24).decode("ascii"),
            "public_key": base64.b64encode(b"\x02" * 32).decode("ascii"),
            "jws": "header.payload.signature",
            "edns_score": 0.15,
            "capabilities": ["INVALID CAP!"],  # Invalid pattern
        }
        raw = json.dumps(payload).encode("utf-8")
        parsed = NhpKnkParser.parse(raw)
        with pytest.raises(KnkParseError, match="Invalid capability"):
            await NhpKnkParser.validate_schema(parsed)

    @pytest.mark.asyncio
    async def test_full_validate_passes(self):
        """Full validation pipeline should pass for a valid payload."""
        import time
        payload = {
            "version": "1.0",
            "node_id": "agent-001",
            "timestamp": int(time.time()),
            "nonce": base64.b64encode(b"\x01" * 24).decode("ascii"),
            "public_key": base64.b64encode(b"\x02" * 32).decode("ascii"),
            "jws": "header.payload.signature",
            "edns_score": 0.15,
            "capabilities": ["soc-analysis", "sba-read"],
        }
        raw = json.dumps(payload).encode("utf-8")
        result = await NhpKnkParser.full_validate(raw)
        assert result.node_id == "agent-001"
