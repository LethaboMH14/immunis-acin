# test_pipeline.py — run from project root
import asyncio
import logging
import traceback

# Configure detailed logging
logging.basicConfig(
    level=logging.DEBUG, 
    format='%(asctime)s | %(levelname)s | %(name)s: %(message)s'
)

from backend.orchestrator import get_orchestrator
from backend.models.schemas import ThreatInput

async def main():
    orch = get_orchestrator()
    threat = ThreatInput(
        content="Lumela ntate, ke kopa o ntumelle ho fetisetsa chelete ea R2,450,000 ho akhaonto ena ka pele. Ke CEO, ho potlakile.",
        vector="email",
        language_hint="st"
    )
    print("=== STARTING PIPELINE ===")
    try:
        result = await orch.process_threat(threat)
        print("=== PIPELINE COMPLETED ===")
        print(f"Result success: {result.success}")
        print(f"Stages completed: {[s.value for s in result.stages_completed]}")
        print(f"Is threat: {result.is_threat}")
        print(f"Antibody created: {result.antibody is not None}")
        if result.antibody:
            print(f"Antibody ID: {result.antibody.antibody_id}")
            print(f"Antibody status: {result.antibody.status}")
        print(f"Error message: {result.error_message}")
    except Exception as e:
        print(f"=== PIPELINE FAILED: {e} ===")
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
