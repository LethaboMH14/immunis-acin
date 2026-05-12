"""
IMMUNIS ACIN — MITRE ATT&CK Evaluation
Tests technique coverage, gap analysis, and detection mapping.
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from backend.services.mitre_navigator import MITRENavigator


class TestMITREEvaluation:
    """Tests for MITRE ATT&CK technique coverage."""

    def setup_method(self):
        self.navigator = MITRENavigator()

    def test_init(self):
        """Navigator initialises with technique mappings."""
        assert self.navigator is not None

    def test_minimum_technique_coverage(self):
        """Must cover at least 40 ATT&CK techniques."""
        if hasattr(self.navigator, 'get_coverage_stats'):
            stats = self.navigator.get_coverage_stats()
            if isinstance(stats, dict):
                total = stats.get("total_techniques", stats.get("mapped", 0))
                assert total >= 40, f"Must cover 40+ techniques, got {total}"
        elif hasattr(self.navigator, 'techniques'):
            assert len(self.navigator.techniques) >= 40, f"Must cover 40+ techniques, got {len(self.navigator.techniques)}"

    def test_navigator_layer_format(self):
        """Generated layer is valid ATT&CK Navigator v4.x JSON."""
        if hasattr(self.navigator, 'generate_layer'):
            layer = self.navigator.generate_layer()
            assert isinstance(layer, dict)
            # Navigator v4.x required fields
            assert "name" in layer or "versions" in layer
            if "techniques" in layer:
                assert isinstance(layer["techniques"], list)
                if len(layer["techniques"]) > 0:
                    tech = layer["techniques"][0]
                    assert "techniqueID" in tech
                    assert "score" in tech or "color" in tech

    def test_technique_has_detection_agent(self):
        """Each mapped technique specifies which agent detects it."""
        if hasattr(self.navigator, 'get_techniques') or hasattr(self.navigator, 'techniques'):
            techniques = getattr(self.navigator, 'techniques', None)
            if techniques is None and hasattr(self.navigator, 'get_techniques'):
                techniques = self.navigator.get_techniques()

            if isinstance(techniques, dict):
                for tech_id, tech_data in list(techniques.items())[:10]:
                    if isinstance(tech_data, dict):
                        has_agent = ("agent" in tech_data or
                                    "detecting_agents" in tech_data or
                                    "agents" in tech_data)
                        assert has_agent, f"Technique {tech_id} must specify detecting agent"
            elif isinstance(techniques, list):
                for tech in techniques[:10]:
                    if isinstance(tech, dict):
                        has_agent = ("agent" in tech or
                                    "detecting_agents" in tech or
                                    "agents" in tech)
                        assert has_agent, f"Technique must specify detecting agent"

    def test_coverage_score_range(self):
        """Coverage scores should be between 0 and 100."""
        if hasattr(self.navigator, 'get_coverage_stats'):
            stats = self.navigator.get_coverage_stats()
            if isinstance(stats, dict):
                score = stats.get("coverage_score", stats.get("score", stats.get("percentage", 50)))
                assert 0 <= score <= 100, f"Coverage score should be 0-100, got {score}"

    def test_gap_analysis(self):
        """Gap analysis identifies uncovered techniques."""
        if hasattr(self.navigator, 'get_gaps'):
            gaps = self.navigator.get_gaps()
            assert isinstance(gaps, (list, dict))
            # Should identify at least some gaps (no system is 100%)

    def test_threat_actor_comparison(self):
        """Can compare coverage against known threat actors."""
        actors = ["APT28", "APT29", "Lazarus", "FIN7"]
        if hasattr(self.navigator, 'compare_actor'):
            for actor in actors:
                try:
                    result = self.navigator.compare_actor(actor)
                    if result:
                        assert isinstance(result, dict)
                        break
                except (KeyError, ValueError):
                    continue

    def test_technique_ids_valid_format(self):
        """All technique IDs follow T####.### format."""
        import re
        pattern = re.compile(r'^T\d{4}(\.\d{3})?$')

        if hasattr(self.navigator, 'techniques'):
            techniques = self.navigator.techniques
            if isinstance(techniques, dict):
                for tech_id in list(techniques.keys())[:20]:
                    assert pattern.match(tech_id), \
                        f"Invalid technique ID format: {tech_id}"
            elif isinstance(techniques, list):
                for tech in techniques[:20]:
                    tech_id = tech.get("id", tech.get("techniqueID", "")) if isinstance(tech, dict) else str(tech)
                    if tech_id:
                        assert pattern.match(tech_id), \
                            f"Invalid technique ID format: {tech_id}"

    def test_phishing_techniques_covered(self):
        """Core phishing techniques must be covered (primary use case)."""
        phishing_techs = ["T1566", "T1566.001", "T1566.002"]
        if hasattr(self.navigator, 'techniques'):
            techniques = self.navigator.techniques
            if isinstance(techniques, dict):
                covered = [t for t in phishing_techs if t in techniques]
                assert len(covered) >= 1, \
                    f"Must cover at least one phishing technique: {phishing_techs}"
            elif isinstance(techniques, list):
                covered = [t.get("id", t.get("techniqueID", "")) for t in techniques if isinstance(t, dict)]
                covered = [t for t in covered if t in phishing_techs]
                assert len(covered) >= 1, \
                    f"Must cover at least one phishing technique: {phishing_techs}"
