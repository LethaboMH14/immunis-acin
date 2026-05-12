#!/usr/bin/env python3
"""
Simple demo seeder - populates dashboard with basic threats
"""

import asyncio
import aiohttp

async def main():
    """Simple seeder that submits basic threats."""
    print("🚀 IMMUNIS ACIN — Simple Dashboard Seeder")
    print("=" * 50)
    
    # Basic demo threats
    threats = [
        {
            "name": "Sesotho BEC",
            "content": "Dumela Mme Ndlovu, re hloka hore o fetise R2,450,000 ho account e ncha bakeng sa projeke ea matjhaba e potlakileng.",
            "vector": "email",
            "language_hint": "st"
        },
        {
            "name": "isiZulu Authority",
            "content": "Sawubona Mnumzane, ngiyisisebenzi seSARS. Kumele ukuthi ukhokhe inhlawulo ye-R45,000 ngaphambi kwehora lesi-5 namhlanje.",
            "vector": "email", 
            "language_hint": "zu"
        },
        {
            "name": "Arabic Invoice",
            "content": "عزيزي المدير المالي، يرجى تحويل مبلغ 500,000 درهم إلى الحساب الجديد فوراً. هذا أمر عاجل من الرئيس التنفيذي.",
            "vector": "email",
            "language_hint": "ar"
        },
        {
            "name": "English Ransomware",
            "content": "URGENT: Your files have been encrypted by MedusaLocker 3.0. Pay 50 BTC within 72 hours or all patient records will be published.",
            "vector": "email",
            "language_hint": "en"
        },
        {
            "name": "Mandarin Supply Chain",
            "content": "紧急通知：请立即更新固件版本至v3.2.1。下载链接：http://firmware-update.evil.com/patch.exe",
            "vector": "email",
            "language_hint": "zh"
        },
        {
            "name": "Russian APT",
            "content": "Уважаемый администратор, обнаружена критическая уязвимость в SCADA системе. Установите патч: http://fstec-update.ru/patch.msi",
            "vector": "email",
            "language_hint": "ru"
        }
    ]
    
    async with aiohttp.ClientSession() as session:
        print("\n📤 Submitting demo threats...")
        submitted_ids = []
        
        for i, threat in enumerate(threats):
            try:
                async with session.post(
                    "http://localhost:8000/api/threats",
                    json={
                        "content": threat["content"],
                        "source": "demo",
                        "vector": threat["vector"],
                        "language_hint": threat["language_hint"]
                    }
                ) as resp:
                    if resp.status in (200, 202):
                        result = await resp.json()
                        incident_id = result.get('incident_id')
                        if incident_id:
                            print(f"✓ {i+1}. {threat['name']}: {incident_id}")
                            submitted_ids.append(incident_id)
                        else:
                            print(f"⚠ {i+1}. {threat['name']}: No incident ID")
                    else:
                        print(f"✗ {i+1}. {threat['name']}: HTTP {resp.status}")
            except Exception as e:
                print(f"✗ {i+1}. {threat['name']}: {e}")
            
            await asyncio.sleep(1)  # Brief pause between submissions
        
        if submitted_ids:
            print(f"\n✅ Successfully submitted {len(submitted_ids)} threats")
            print("⏳ Waiting for processing to complete...")
            await asyncio.sleep(10)  # Wait for processing
            
            # Check final state
            try:
                async with session.get("http://localhost:8000/api/health") as resp:
                    if resp.status == 200:
                        health = await resp.json()
                        print(f"🛡️ Final immunity score: {health.get('immunity_score', 0)}")
                        print(f"📈 Threats processed: {health.get('threats_processed', 0)}")
                        print(f"🦠 Antibodies created: {health.get('antibody_count', 0)}")
            except Exception:
                pass
            
            print(f"\n🌐 Open http://localhost:3000 to see the dashboard!")
        else:
            print("✗ No threats were submitted successfully")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n⚠ Seeding interrupted by user")
    except Exception as e:
        print(f"\n✗ Fatal error: {e}")
