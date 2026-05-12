#!/usr/bin/env python3
"""
IMMUNIS ACIN — Demo Dashboard Seeder
Pre-populates the dashboard with realistic data for 10-minute demo.

Usage:
    python demo/seed_dashboard.py
"""

import asyncio
import json
import sys
import time
from pathlib import Path
from datetime import datetime, timezone

import aiohttp
import numpy as np

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import individual threat files to avoid null byte issues
import json
from pathlib import Path

# Load threat data directly
threat_files = {
    "Sesotho BEC": "demo/synthetic_threats/sesotho_bec.json",
    "isiZulu Authority": "demo/synthetic_threats/zulu_authority.json", 
    "Arabic Invoice": "demo/synthetic_threats/arabic_invoice.json",
    "English Ransomware": "demo/synthetic_threats/english_ransomware.json",
    "Mandarin Supply Chain": "demo/synthetic_threats/mandarin_supply.json",
    "Russian APT": "demo/synthetic_threats/russian_apt.json",
}

def load_threat(name, filepath):
    """Load a single threat file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
            # Extract the content field from the nested structure
            if 'threat' in data:
                content = data['threat'].get('body', data['threat'].get('content', 'Demo threat content'))
                vector = data['threat'].get('vector', 'email')
                language_hint = data['threat'].get('language_hint', 'auto')
            else:
                content = data.get('body', data.get('content', 'Demo threat content'))
                vector = data.get('vector', 'email')
                language_hint = data.get('language_hint', 'auto')
            
            return {
                "name": name, 
                "data": {
                    "content": content,
                    "vector": vector,
                    "language_hint": language_hint
                }
            }
    except Exception as e:
        print(f"⚠ Could not load {name}: {e}")
        return {"name": name, "data": {"content": "Demo threat", "vector": "email"}}


async def submit_threat(session, threat_data, source="demo"):
    """Submit a single threat to the API."""
    try:
        print(f"  Debug: threat_data keys: {list(threat_data.keys())}")
        print(f"  Debug: threat_data content: {threat_data.get('data', {}).get('content', 'MISSING')[:100]}...")
        
        async with session.post(
            "http://localhost:8000/api/threats",
            json={
                "content": threat_data["data"]["content"],
                "source": source,
                "vector": threat_data["data"].get("vector", "email"),
                "language_hint": threat_data["data"].get("language_hint", "auto")
            }
        ) as resp:
            if resp.status in (200, 202):
                result = await resp.json()
                print(f"✓ Submitted {threat_data['name']}: {result.get('incident_id', 'N/A')}")
                return result.get('incident_id')
            else:
                print(f"✗ Failed to submit {threat_data['name']}: HTTP {resp.status}")
                return None
    except Exception as e:
        print(f"✗ Error submitting {threat_data['name']}: {e}")
        return None


async def wait_for_processing(session, incident_id, timeout=30):
    """Wait for threat processing to complete."""
    if not incident_id:
        return False
        
    start_time = time.time()
    print(f"⏳ Waiting for {incident_id} processing...")
    
    while time.time() - start_time < timeout:
        try:
            async with session.get(f"http://localhost:8000/api/pipeline/status/{incident_id}") as resp:
                if resp.status == 200:
                    status = await resp.json()
                    if status.get("stage") == "completed":
                        print(f"✓ {incident_id} processing completed")
                        return True
                    elif status.get("stage") == "failed":
                        print(f"✗ {incident_id} processing failed")
                        return False
                    else:
                        print(f"  {incident_id} stage: {status.get('stage', 'unknown')}")
        except Exception:
            pass
        
        await asyncio.sleep(2)
    
    print(f"⚠ {incident_id} processing timeout")
    return False


async def check_antibodies(session):
    """Check how many antibodies exist."""
    try:
        async with session.get("http://localhost:8000/api/antibodies") as resp:
            if resp.status == 200:
                data = await resp.json()
                count = data.get("total", 0)
                print(f"📊 Antibodies in library: {count}")
                return count
    except Exception as e:
        print(f"✗ Error checking antibodies: {e}")
        return 0


async def check_battleground(session):
    """Check battleground history."""
    try:
        async with session.get("http://localhost:8000/api/battleground/history") as resp:
            if resp.status == 200:
                data = await resp.json()
                count = len(data) if isinstance(data, list) else 0
                print(f"⚔️ Battle sessions: {count}")
                return count
    except Exception as e:
        print(f"✗ Error checking battleground: {e}")
        return 0


async def check_mesh(session):
    """Check mesh status."""
    try:
        async with session.get("http://localhost:8000/api/mesh/status") as resp:
            if resp.status == 200:
                data = await resp.json()
                nodes = data.get("nodes", 0)
                print(f"🌐 Mesh nodes: {len(nodes)}")
                return len(nodes)
    except Exception as e:
        print(f"✗ Error checking mesh: {e}")
        return 0


async def main():
    """Main seeder function."""
    print("🚀 IMMUNIS ACIN — Dashboard Seeder")
    print("=" * 50)
    
    # Demo threats to submit
    threats = []
    for name, filepath in threat_files.items():
        threat_data = load_threat(name, filepath)
        threats.append({"name": name, "data": threat_data})
    
    async with aiohttp.ClientSession() as session:
        print("\n📤 STEP 1: Submitting demo threats...")
        submitted_ids = []
        
        for threat in threats:
            incident_id = await submit_threat(session, threat["data"])
            if incident_id:
                submitted_ids.append(incident_id)
            await asyncio.sleep(1)  # Brief pause between submissions
        
        if not submitted_ids:
            print("✗ No threats were submitted successfully")
            return
        
        print(f"\n⏳ STEP 2: Waiting for processing to complete...")
        for incident_id in submitted_ids:
            await wait_for_processing(session, incident_id)
        
        print("\n📊 STEP 3: Verifying dashboard state...")
        
        # Wait a bit more for all background processing
        await asyncio.sleep(3)
        
        # Check final state
        antibody_count = await check_antibodies(session)
        battle_count = await check_battleground(session)
        mesh_count = await check_mesh(session)
        
        # Get final immunity score
        try:
            async with session.get("http://localhost:8000/api/immunity") as resp:
                if resp.status == 200:
                    immunity_data = await resp.json()
                    immunity_score = immunity_data.get("immunity_score", 0)
                    threats_processed = immunity_data.get("total_threats_processed", 0)
                    print(f"🛡️ Final immunity score: {immunity_score}")
                    print(f"📈 Threats processed: {threats_processed}")
        except Exception:
            pass
        
        print("\n" + "=" * 50)
        print("📋 DASHBOARD SEEDING COMPLETE")
        print(f"✅ Antibodies created: {antibody_count}")
        print(f"✅ Battle sessions: {battle_count}")
        print(f"✅ Mesh nodes: {mesh_count}")
        print(f"✅ Ready for demo recording!")
        
        # Summary for demo
        print("\n🎯 DEMO READY SUMMARY:")
        print("   • Immunity score should be > 70")
        print("   • 6+ threats should be visible in feed")
        print("   • Multiple antibodies should be listed")
        print("   • Battle history should show evolution")
        print("   • Mesh visualization should be active")
        print("\n🌐 Open http://localhost:3000 to see the dashboard!")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n⚠ Seeding interrupted by user")
    except Exception as e:
        print(f"\n✗ Fatal error: {e}")
        sys.exit(1)
