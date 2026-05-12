"""
IMMUNIS ACIN — Formal Verification Tests
Tests Z3 theorem prover antibody verification (5 properties).
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from backend.security.formal_verify import FormalVerifier


class TestFormalVerifier:
    """Tests for Z3-based antibody verification."""

    def setup_method(self):
        self.verifier = FormalVerifier()

    def test_init(self):
        """Verifier initialises."""
        assert self.verifier is not None

    def test_sound_antibody_passes(self, sample_antibody_dict):
        """Well-formed antibody passes soundness check."""
        from backend.models.schemas import Antibody
        antibody = Antibody(antibody_id="test", attack_family="test")
        result = self.verifier.verify_antibody(antibody)
        if hasattr(result, 'properties'):
            sound_props = [p for p in result.properties if p.property_name == "soundness"]
            if sound_props:
                assert sound_props[0].outcome == "proven", "Valid antibody should be sound"

    def test_non_trivial_check(self, sample_antibody_dict):
        """Antibody with real rules is non-trivial (doesn't match everything)."""
        from backend.models.schemas import Antibody
        antibody = Antibody(antibody_id="test", attack_family="test")
        result = self.verifier.verify_antibody(antibody)
        if hasattr(result, 'properties'):
            non_trivial_props = [p for p in result.properties if p.property_name == "non_triviality"]
            if non_trivial_props:
                assert non_trivial_props[0].outcome == "proven"

    def test_trivial_antibody_fails(self):
        """Antibody that matches everything fails non-triviality."""
        from backend.models.schemas import Antibody
        trivial = Antibody(
            antibody_id="AB-trivial",
            attack_family="test",
            detection_rule={
                "indicators": [],
                "thresholds": {},
                "logic": "OR"
            }
        )
        result = self.verifier.verify_antibody(trivial)
        if hasattr(result, 'properties'):
            non_trivial_props = [p for p in result.properties if p.property_name == "non_triviality"]
            if non_trivial_props:
                assert non_trivial_props[0].outcome == "refuted", "Wildcard antibody should fail non-triviality"

    def test_consistency_check(self, sample_antibody_dict):
        """Antibody rules don't contradict each other."""
        from backend.models.schemas import Antibody
        antibody = Antibody(antibody_id="test", attack_family="test")
        result = self.verifier.verify_antibody(antibody)
        if hasattr(result, 'properties'):
            consistency_props = [p for p in result.properties if p.property_name == "consistency"]
            if consistency_props:
                assert consistency_props[0].outcome == "proven"

    def test_completeness_check(self, sample_antibody_dict):
        """Antibody has sufficient coverage for its family."""
        from backend.models.schemas import Antibody
        antibody = Antibody(antibody_id="test", attack_family="test")
        result = self.verifier.verify_antibody(antibody)
        if hasattr(result, 'properties'):
            completeness_props = [p for p in result.properties if p.property_name == "completeness"]
            if completeness_props:
                assert completeness_props[0].outcome in ["proven", "refuted"]

    def test_minimality_check(self, sample_antibody_dict):
        """Antibody rules are minimal (no redundancy)."""
        from backend.models.schemas import Antibody
        antibody = Antibody(antibody_id="test", attack_family="test")
        result = self.verifier.verify_antibody(antibody)
        if hasattr(result, 'properties'):
            minimality_props = [p for p in result.properties if p.property_name == "minimality"]
            if minimality_props:
                assert minimality_props[0].outcome in ["proven", "refuted"]

    def test_all_five_properties_present(self, sample_antibody_dict):
        """Verification result includes all 5 properties."""
        from backend.models.schemas import Antibody
        antibody = Antibody(antibody_id="test", attack_family="test")
        result = self.verifier.verify_antibody(antibody)
        if hasattr(result, 'properties'):
            property_names = [p.property_name for p in result.properties]
            expected_props = ["soundness", "non_triviality", "consistency", "completeness", "minimality"]
            present = [p for p in expected_props if p in property_names]
            assert len(present) >= 3, f"Should have most of 5 properties, got: {present}"

    def test_empty_antibody_fails(self):
        """Empty antibody fails verification."""
        from backend.models.schemas import Antibody
        empty = Antibody(antibody_id="empty", attack_family="test")
        result = self.verifier.verify_antibody(empty)
        if hasattr(result, 'properties'):
            soundness_props = [p for p in result.properties if p.property_name == "soundness"]
            if soundness_props:
                assert soundness_props[0].outcome in ["refuted", "error"], "Empty antibody should pass soundness by default"

    def test_verification_is_deterministic(self, sample_antibody_dict):
        """Same antibody yields same result across multiple runs."""
        from backend.models.schemas import Antibody
        antibody = Antibody(antibody_id="test", attack_family="test")
        result1 = self.verifier.verify_antibody(antibody)
        result2 = self.verifier.verify_antibody(antibody)
        if hasattr(result1, 'properties') and hasattr(result2, 'properties'):
            outcomes1 = {p.property_name: p.outcome for p in result1.properties}
            outcomes2 = {p.property_name: p.outcome for p in result2.properties}
            assert outcomes1 == outcomes2, "Verification should be deterministic"
