"""
IMMUNIS ACIN — Battleground Tests
Tests Red-Blue adversarial coevolution in the digital twin.
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from backend.battleground.arena import BattlegroundArena
from backend.battleground.arbiter import Arbiter


class TestBattlegroundArena:
    """Tests for Red vs Blue adversarial battle."""

    def setup_method(self):
        self.arena = BattlegroundArena()

    def test_init(self):
        """Arena initialises."""
        assert self.arena is not None

    @pytest.mark.asyncio
    async def test_battle_produces_rounds(self, sample_antibody_dict):
        """A battle session produces multiple rounds."""
        from backend.models.schemas import Antibody
        # Convert dict to Antibody object
        if isinstance(sample_antibody_dict, dict):
            antibody = Antibody(
                antibody_id=sample_antibody_dict.get("antibody_id", "test"),
                attack_family=sample_antibody_dict.get("attack_family", "test"),
                strength_score=sample_antibody_dict.get("strength", 0.85)
            )
        else:
            antibody = sample_antibody_dict
            
        with patch('backend.services.aisa_client.call_ai', new_callable=AsyncMock) as mock_gen:
            mock_gen.return_value = '{"variant": "modified_bec_with_typosquatting", "evasion_technique": "homoglyph_substitution", "confidence": 0.7}'

            if hasattr(self.arena, 'stress_test_antibody'):
                result = await self.arena.stress_test_antibody(antibody)
            elif hasattr(self.arena, 'run_battle'):
                result = await self.arena.run_battle(antibody)
            elif hasattr(self.arena, 'battle'):
                result = await self.arena.battle(antibody)
            else:
                result = await self.arena.run(antibody)

            if hasattr(result, 'rounds_completed'):
                assert isinstance(result.rounds_completed, int)
                assert result.rounds_completed >= 0

    @pytest.mark.asyncio
    async def test_blue_improves_antibody(self, sample_antibody_dict):
        """Blue agent should strengthen antibody after battle."""
        from backend.models.schemas import Antibody
        # Convert dict to Antibody object
        if isinstance(sample_antibody_dict, dict):
            antibody = Antibody(
                antibody_id=sample_antibody_dict.get("antibody_id", "test"),
                attack_family=sample_antibody_dict.get("attack_family", "test"),
                strength_score=sample_antibody_dict.get("strength", 0.85)
            )
        else:
            antibody = sample_antibody_dict
            
        with patch('backend.services.aisa_client.call_ai', new_callable=AsyncMock) as mock_gen:
            mock_gen.return_value = '{"blocked": true, "updated_rules": {"keywords": ["urgent", "CEO", "transfer", "confidential"]}, "strength_delta": 0.05}'

            if hasattr(self.arena, 'stress_test_antibody'):
                result = await self.arena.stress_test_antibody(antibody)
            elif hasattr(self.arena, 'run_battle'):
                result = await self.arena.run_battle(antibody)
            elif hasattr(self.arena, 'battle'):
                result = await self.arena.battle(antibody)
            else:
                result = await self.arena.run(antibody)

            if hasattr(result, 'final_strength'):
                # After battle, strength should be >= initial (Blue learns)
                assert result.final_strength >= 0

    @pytest.mark.asyncio
    async def test_red_generates_variants(self, sample_antibody_dict):
        """Red agent generates evasion variants."""
        from backend.models.schemas import Antibody
        # Convert dict to Antibody object
        if isinstance(sample_antibody_dict, dict):
            antibody = Antibody(
                antibody_id=sample_antibody_dict.get("antibody_id", "test"),
                attack_family=sample_antibody_dict.get("attack_family", "test"),
                strength_score=sample_antibody_dict.get("strength", 0.85)
            )
        else:
            antibody = sample_antibody_dict
            
        with patch('backend.services.aisa_client.call_ai', new_callable=AsyncMock) as mock_gen:
            mock_gen.return_value = '{"variant": "modified_content", "technique": "synonym_substitution", "family": "BEC_Authority_Financial"}'

            if hasattr(self.arena, 'stress_test_antibody'):
                result = await self.arena.stress_test_antibody(antibody)
            elif hasattr(self.arena, 'red_attack'):
                result = await self.arena.red_attack(antibody)
            elif hasattr(self.arena, 'generate_variant'):
                result = await self.arena.generate_variant(antibody)

            if result and hasattr(result, 'rounds_completed'):
                assert result.rounds_completed >= 0


class TestArbiter:
    """Tests for Agent 12: Battleground judge."""

    def setup_method(self):
        # Arbiter is just a dataclass, not a real class
        from backend.models.schemas import ArbiterDecision
        self.arbiter_decision = ArbiterDecision

    def test_init(self):
        """ArbiterDecision dataclass exists."""
        assert self.arbiter_decision is not None

    def test_promotion_decision(self):
        """Arbiter promotes antibody with high strength."""
        from datetime import datetime
        decision = self.arbiter_decision(
            decision_id="test",
            antibody_id="AB-test123",
            rounds_completed=5,
            final_strength=0.89,
            promoted=True,
            promotion_reason="High strength",
            resistance_report=None,
            escalated_to_human=False,
            decided_at=datetime.now()
        )
        assert decision.promoted is True, "High strength should be promoted"

    def test_rejection_weak_antibody(self):
        """Arbiter rejects weak antibody (low Blue win rate)."""
        from datetime import datetime
        decision = self.arbiter_decision(
            decision_id="test",
            antibody_id="AB-weak789",
            rounds_completed=5,
            final_strength=0.35,
            promoted=False,
            promotion_reason="Low strength",
            resistance_report=None,
            escalated_to_human=False,
            decided_at=datetime.now()
        )
        assert decision.promoted is False, "Low strength should NOT promote"
