"""
IMMUNIS ACIN — Arbiter (Agent 12)
Battleground judge: scores battles, decides promotion, escalation.
"""
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class Arbiter:
    """Agent 12: Battleground judge and antibody promotion authority."""

    def __init__(self, promotion_threshold: float = 0.7, min_rounds: int = 3):
        self.promotion_threshold = promotion_threshold
        self.min_rounds = min_rounds
        self.history = []

    def judge(self, battle_result: Dict) -> Dict:
        """Judge a battle result and decide on promotion.
        
        Args:
            battle_result: Dict with rounds, blue_wins, red_wins, final_strength
            
        Returns:
            Decision dict with promoted, score, reasoning
        """
        rounds = battle_result.get("rounds", 0)
        blue_wins = battle_result.get("blue_wins", 0)
        red_wins = battle_result.get("red_wins", 0)
        strength = battle_result.get("final_strength", 0.5)
        antibody_id = battle_result.get("antibody_id", "unknown")

        total_rounds = blue_wins + red_wins
        if total_rounds == 0:
            win_rate = 0.0
        else:
            win_rate = blue_wins / total_rounds

        # Composite score: 60% win rate + 40% strength
        score = 0.6 * win_rate + 0.4 * strength

        # Promotion decision
        promoted = score >= self.promotion_threshold and total_rounds >= self.min_rounds

        decision = {
            "antibody_id": antibody_id,
            "promoted": promoted,
            "promote": promoted,
            "score": score,
            "win_rate": win_rate,
            "strength": strength,
            "rounds_played": total_rounds,
            "reasoning": self._generate_reasoning(win_rate, strength, promoted)
        }

        self.history.append(decision)
        logger.info(f"Arbiter decision for {antibody_id}: {'PROMOTED' if promoted else 'REJECTED'} (score={score:.2f})")
        return decision

    def decide(self, battle_result: Dict) -> Dict:
        """Alias for judge()."""
        return self.judge(battle_result)

    def evaluate(self, battle_result: Dict) -> Dict:
        """Alias for judge()."""
        return self.judge(battle_result)

    def _generate_reasoning(self, win_rate: float, strength: float, promoted: bool) -> str:
        if promoted:
            if win_rate >= 0.9:
                return "Exceptional defense rate. Antibody demonstrates robust variant coverage."
            elif win_rate >= 0.7:
                return "Strong defense with acceptable variant coverage. Promoted for mesh distribution."
            else:
                return "Meets minimum threshold. Promoted with monitoring flag."
        else:
            if win_rate < 0.5:
                return "Blue win rate below 50%. Antibody requires strengthening before promotion."
            else:
                return "Composite score below promotion threshold. Needs additional battle rounds."
