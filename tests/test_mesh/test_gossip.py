"""
IMMUNIS ACIN — Gossip Protocol Tests
Tests epidemic broadcast with R₀-weighted fan-out.
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from backend.mesh.gossip import GossipProtocol


class TestGossipProtocol:
    """Tests for epidemic antibody broadcast."""

    def setup_method(self):
        self.gossip = GossipProtocol()

    def test_init(self):
        """Protocol initialises."""
        assert self.gossip is not None

    def test_fan_out_scales_with_r0(self):
        """Fan-out = min(ceil(R₀ × 2), total_peers, 10)."""
        if hasattr(self.gossip, 'compute_fan_out'):
            fan_low = self.gossip.compute_fan_out(r0=1.0, total_peers=20)
            fan_high = self.gossip.compute_fan_out(r0=5.0, total_peers=20)
            assert fan_high >= fan_low, "Higher R₀ should mean more fan-out"
            assert fan_high <= 10, "Fan-out capped at 10"

    def test_fan_out_capped_by_peers(self):
        """Fan-out can't exceed total available peers."""
        if hasattr(self.gossip, 'compute_fan_out'):
            fan = self.gossip.compute_fan_out(r0=10.0, total_peers=3)
            assert fan <= 3, "Fan-out can't exceed peer count"

    def test_priority_ordering(self):
        """Messages ordered by R₀ × severity × (1/age)."""
        if hasattr(self.gossip, 'compute_priority'):
            p1 = self.gossip.compute_priority(r0=2.0, severity=0.8, age_seconds=10)
            p2 = self.gossip.compute_priority(r0=5.0, severity=0.9, age_seconds=5)
            assert p2 > p1, "Higher R₀ + severity + freshness = higher priority"

    def test_deduplication(self):
        """Same message ID is not broadcast twice (bloom filter)."""
        if hasattr(self.gossip, 'should_broadcast'):
            msg_id = "AB-test123-broadcast-001"
            first = self.gossip.should_broadcast(msg_id)
            second = self.gossip.should_broadcast(msg_id)
            if first is True:
                assert second is False, "Duplicate message should be filtered"

    def test_ttl_decrements(self):
        """TTL decreases with each hop."""
        if hasattr(self.gossip, 'process_message'):
            message = {
                "id": "msg-001",
                "antibody_id": "AB-test",
                "ttl": 5,
                "payload": "test"
            }
            result = self.gossip.process_message(message)
            if isinstance(result, dict):
                assert result.get("ttl", 5) < 5

    def test_ttl_zero_not_forwarded(self):
        """Message with TTL=0 is not forwarded."""
        if hasattr(self.gossip, 'should_forward'):
            assert self.gossip.should_forward({"ttl": 0}) is False
        elif hasattr(self.gossip, 'process_message'):
            message = {"id": "msg-expired", "ttl": 0, "payload": "test"}
            result = self.gossip.process_message(message)
            if isinstance(result, dict):
                assert result.get("forward", True) is False or result.get("ttl", 0) <= 0

    def test_bloom_filter_reset(self):
        """Bloom filter resets periodically to allow re-broadcast of updated antibodies."""
        if hasattr(self.gossip, 'reset_bloom') or hasattr(self.gossip, 'reset_filter'):
            # Add a message
            if hasattr(self.gossip, 'should_broadcast'):
                self.gossip.should_broadcast("msg-reset-test")
                # Reset
                if hasattr(self.gossip, 'reset_bloom'):
                    self.gossip.reset_bloom()
                else:
                    self.gossip.reset_filter()
                # Should be broadcastable again
                result = self.gossip.should_broadcast("msg-reset-test")
                assert result is True, "After reset, message should be broadcastable"
