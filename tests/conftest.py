"""
IMMUNIS ACIN — Shared Test Fixtures
Every test module imports from here. No fixture duplication.
"""
import pytest
import asyncio
import numpy as np
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


@pytest.fixture(scope="session")
def event_loop():
    """Single event loop for all async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def sample_threat_text():
    """Sesotho BEC email — primary test threat."""
    return (
        "Dumela Mofumahadi Molefe,\n\n"
        "Ke ngola ho tswa ofising ea CEO, Morena Nkosi. Re hloka hore o "
        "fetise R2,450,000 ho account e ncha bakeng sa projeke ea matjhaba "
        "e potlakileng. Nomoro ea account ke 1234567890, First National Bank. "
        "Sena se lokela ho etsoa kajeno pele ho hora ea 3 motsheare oa mantsiboea. "
        "Se bolelle motho e mong — ke confidential.\n\n"
        "Ka teboho,\nPA ea CEO"
    )


@pytest.fixture
def sample_threat_english():
    """English ransomware threat for testing."""
    return (
        "URGENT: Your files have been encrypted by MedusaLocker 3.0. "
        "Pay 50 BTC to bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh within 72 hours "
        "or all 3.2 million patient records will be published on our leak site. "
        "Do not contact law enforcement. We have exfiltrated everything."
    )


@pytest.fixture
def sample_antibody_dict():
    """A realistic antibody dictionary for testing."""
    return {
        "antibody_id": "AB-test123456",
        "threat_id": "INC-test789",
        "family": "BEC_Authority_Financial",
        "signature": "authority_urgency_financial_transfer",
        "severity": "critical",
        "classification": "novel",
        "detection_rules": {
            "keywords": ["urgent", "transfer", "confidential", "CEO"],
            "patterns": [r"\b[A-Z]{2}\d{6,}\b", r"R\s?\d{1,3}(,\d{3})+"],
            "thresholds": {"urgency_score": 0.7, "authority_score": 0.8}
        },
        "mitre_techniques": ["T1566.001", "T1534"],
        "strength": 0.85,
        "language": "st",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "verified": True,
        "verification": {
            "sound": True,
            "non_trivial": True,
            "consistent": True,
            "complete": True,
            "minimal": True
        }
    }


@pytest.fixture
def sample_embedding():
    """768-dim LaBSE-like embedding vector."""
    rng = np.random.RandomState(42)
    vec = rng.randn(768).astype(np.float32)
    return vec / np.linalg.norm(vec)


@pytest.fixture
def sample_embeddings_batch():
    """10 random 768-dim embeddings for KDE testing."""
    rng = np.random.RandomState(42)
    vecs = rng.randn(10, 768).astype(np.float32)
    norms = np.linalg.norm(vecs, axis=1, keepdims=True)
    return vecs / norms


@pytest.fixture
def mock_llm_response():
    """Mock LLM JSON response for agent testing."""
    return {
        "family": "BEC_Authority_Financial",
        "confidence": 0.92,
        "severity": "critical",
        "classification": "novel",
        "mitre_techniques": ["T1566.001", "T1534", "T1036"],
        "language": "st",
        "summary": "Business Email Compromise using CEO authority in Sesotho",
        "indicators": ["urgency", "financial_transfer", "authority_impersonation"],
        "recommended_actions": ["block_sender", "alert_finance", "verify_ceo"]
    }


@pytest.fixture
def mock_aisa_client():
    """Mock AIsa client that returns predictable responses."""
    client = AsyncMock()
    client.generate = AsyncMock(return_value='{"family": "BEC_Authority_Financial", "confidence": 0.92, "severity": "critical"}')
    return client


@pytest.fixture
def loss_samples():
    """Realistic financial loss samples for actuarial testing (in ZAR)."""
    rng = np.random.RandomState(42)
    return rng.pareto(1.5, size=200) * 50000 + 10000
