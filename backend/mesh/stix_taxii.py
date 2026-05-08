"""
IMMUNIS ACIN — STIX 2.1 Export + TAXII 2.1 Server

WHY: IMMUNIS antibodies are powerful, but they're only useful to
IMMUNIS nodes. The broader cybersecurity ecosystem uses STIX
(Structured Threat Information Expression) and TAXII (Trusted
Automated Exchange of Intelligence Information) for threat
intelligence sharing.

By exporting antibodies as STIX 2.1 bundles and serving them
via a TAXII 2.1 API, IMMUNIS integrates with:
- SIEMs (Splunk, QRadar, Sentinel)
- TIPs (MISP, OpenCTI, ThreatConnect)
- SOARs (Cortex XSOAR, Phantom)
- Government CERTs and ISACs

STIX objects generated:
- Indicator: detection rule as STIX pattern
- Malware: attack family classification
- Attack-Pattern: MITRE ATT&CK technique mapping
- Relationship: links between objects
- Sighting: when/where the threat was observed
- Note: antibody metadata, verification status

TAXII endpoints:
- GET /taxii2/                    → Discovery
- GET /taxii2/collections/       → List collections
- GET /taxii2/collections/{id}/  → Collection info
- GET /taxii2/collections/{id}/objects/ → Get STIX objects
- POST /taxii2/collections/{id}/objects/ → Add STIX objects
"""

import logging
import json
import hashlib
import uuid
import time
from typing import Optional
from datetime import datetime, timezone
from dataclasses import dataclass, field

logger = logging.getLogger("immunis.mesh.stix_taxii")


# STIX 2.1 constants
STIX_SPEC_VERSION = "2.1"
STIX_NAMESPACE = "immunis-acin"

# TAXII 2.1 constants
TAXII_VERSION = "2.1"
TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"
STIX_MEDIA_TYPE = "application/stix+json;version=2.1"


def _stix_id(object_type: str, seed: str = "") -> str:
    """Generate a deterministic STIX ID."""
    if seed:
        namespace = hashlib.sha256(
            f"{STIX_NAMESPACE}:{object_type}:{seed}".encode()
        ).hexdigest()[:32]
        # Format as UUID v5-like
        uid = f"{namespace[:8]}-{namespace[8:12]}-{namespace[12:16]}-{namespace[16:20]}-{namespace[20:32]}"
    else:
        uid = str(uuid.uuid4())
    return f"{object_type}--{uid}"


def _stix_timestamp() -> str:
    """Generate a STIX-compliant timestamp."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@dataclass
class STIXCollection:
    """A TAXII collection of STIX objects."""
    collection_id: str
    title: str
    description: str
    can_read: bool = True
    can_write: bool = False
    media_types: list[str] = field(
        default_factory=lambda: [STIX_MEDIA_TYPE]
    )
    objects: list[dict] = field(default_factory=list)

    def to_taxii_dict(self) -> dict:
        return {
            "id": self.collection_id,
            "title": self.title,
            "description": self.description,
            "can_read": self.can_read,
            "can_write": self.can_write,
            "media_types": self.media_types,
        }


class STIXExporter:
    """
    Converts IMMUNIS antibodies to STIX 2.1 objects.

    Each antibody generates:
    1. Indicator — the detection rule as a STIX pattern
    2. Malware — the attack family
    3. Attack-Pattern — MITRE ATT&CK mapping
    4. Relationship — links indicator to malware
    5. Sighting — observation metadata
    6. Note — antibody metadata (strength, verification, etc.)
    """

    # MITRE ATT&CK technique to STIX external reference mapping
    MITRE_REFERENCES = {
        "T1566": {"name": "Phishing", "url": "https://attack.mitre.org/techniques/T1566"},
        "T1566.001": {"name": "Spearphishing Attachment", "url": "https://attack.mitre.org/techniques/T1566/001"},
        "T1566.002": {"name": "Spearphishing Link", "url": "https://attack.mitre.org/techniques/T1566/002"},
        "T1534": {"name": "Internal Spearphishing", "url": "https://attack.mitre.org/techniques/T1534"},
        "T1078": {"name": "Valid Accounts", "url": "https://attack.mitre.org/techniques/T1078"},
        "T1190": {"name": "Exploit Public-Facing Application", "url": "https://attack.mitre.org/techniques/T1190"},
        "T1133": {"name": "External Remote Services", "url": "https://attack.mitre.org/techniques/T1133"},
        "T1486": {"name": "Data Encrypted for Impact", "url": "https://attack.mitre.org/techniques/T1486"},
        "T1071": {"name": "Application Layer Protocol", "url": "https://attack.mitre.org/techniques/T1071"},
        "T1059": {"name": "Command and Scripting Interpreter", "url": "https://attack.mitre.org/techniques/T1059"},
        "T1027": {"name": "Obfuscated Files or Information", "url": "https://attack.mitre.org/techniques/T1027"},
        "T1204": {"name": "User Execution", "url": "https://attack.mitre.org/techniques/T1204"},
        "T1036": {"name": "Masquerading", "url": "https://attack.mitre.org/techniques/T1036"},
        "T1598": {"name": "Phishing for Information", "url": "https://attack.mitre.org/techniques/T1598"},
        "T1557": {"name": "Adversary-in-the-Middle", "url": "https://attack.mitre.org/techniques/T1557"},
    }

    # Attack family to malware type mapping
    FAMILY_TO_MALWARE_TYPE = {
        "BEC": "trojan",
        "Phishing": "trojan",
        "Ransomware": "ransomware",
        "Malware": "malware",
        "Spyware": "spyware",
        "Worm": "worm",
        "Rootkit": "rootkit",
        "Backdoor": "backdoor",
        "Dropper": "dropper",
        "Keylogger": "spyware",
        "RAT": "remote-access-trojan",
        "Cryptominer": "resource-exploitation",
    }

    def __init__(self):
        self._export_count: int = 0
        self._identity_id = _stix_id("identity", "immunis-acin")

        logger.info("STIX exporter initialised")

    def export_antibody(
        self,
        antibody: dict,
        incident: Optional[dict] = None,
    ) -> dict:
        """
        Export an antibody as a STIX 2.1 bundle.

        Args:
            antibody: Antibody dict (from database or schema).
            incident: Optional incident dict for sighting data.

        Returns:
            STIX 2.1 Bundle dict.
        """
        objects = []
        now = _stix_timestamp()

        antibody_id = antibody.get("antibody_id", "unknown")
        attack_family = antibody.get("attack_family", "Unknown")
        detection_rule = antibody.get("detection_rule", {})
        indicators = antibody.get("indicators", [])
        mitre_techniques = antibody.get("mitre_techniques", [])
        if isinstance(mitre_techniques, str):
            try:
                mitre_techniques = json.loads(mitre_techniques)
            except (json.JSONDecodeError, TypeError):
                mitre_techniques = []

        # 1. IMMUNIS Identity
        identity = {
            "type": "identity",
            "spec_version": STIX_SPEC_VERSION,
            "id": self._identity_id,
            "created": now,
            "modified": now,
            "name": "IMMUNIS ACIN",
            "description": "Adversarial Coevolutionary Immune Network",
            "identity_class": "system",
            "sectors": ["technology"],
        }
        objects.append(identity)

        # 2. Indicator (detection rule)
        stix_pattern = self._build_stix_pattern(detection_rule, indicators)
        indicator_id = _stix_id("indicator", antibody_id)

        indicator = {
            "type": "indicator",
            "spec_version": STIX_SPEC_VERSION,
            "id": indicator_id,
            "created": now,
            "modified": now,
            "name": f"IMMUNIS Antibody {antibody_id}",
            "description": (
                f"Detection rule for {attack_family} attack family. "
                f"Strength: {antibody.get('strength', 0):.0%}. "
                f"Verification: {antibody.get('verification_status', 'unknown')}."
            ),
            "indicator_types": ["malicious-activity"],
            "pattern": stix_pattern,
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": now,
            "created_by_ref": self._identity_id,
            "confidence": int(antibody.get("strength", 0.5) * 100),
            "labels": [
                f"immunis:family={attack_family}",
                f"immunis:antibody_id={antibody_id}",
                f"immunis:verified={antibody.get('verification_status', 'unknown')}",
            ],
        }

        if antibody.get("languages"):
            languages = antibody["languages"]
            if isinstance(languages, str):
                try:
                    languages = json.loads(languages)
                except (json.JSONDecodeError, TypeError):
                    languages = []
            indicator["labels"].extend(
                [f"immunis:language={lang}" for lang in languages[:5]]
            )

        objects.append(indicator)

        # 3. Malware (attack family)
        malware_id = _stix_id("malware", attack_family)
        malware_type = self.FAMILY_TO_MALWARE_TYPE.get(
            attack_family.split("_")[0], "unknown"
        )

        malware = {
            "type": "malware",
            "spec_version": STIX_SPEC_VERSION,
            "id": malware_id,
            "created": now,
            "modified": now,
            "name": attack_family,
            "description": f"Attack family: {attack_family}",
            "malware_types": [malware_type],
            "is_family": True,
            "created_by_ref": self._identity_id,
        }
        objects.append(malware)

        # 4. Attack Patterns (MITRE ATT&CK)
        for technique in mitre_techniques:
            if isinstance(technique, str):
                technique_id = technique
            elif isinstance(technique, dict):
                technique_id = technique.get("id", technique.get("technique", ""))
            else:
                continue

            ref = self.MITRE_REFERENCES.get(technique_id)
            ap_id = _stix_id("attack-pattern", technique_id)

            attack_pattern = {
                "type": "attack-pattern",
                "spec_version": STIX_SPEC_VERSION,
                "id": ap_id,
                "created": now,
                "modified": now,
                "name": ref["name"] if ref else technique_id,
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": technique_id,
                        "url": ref["url"] if ref else f"https://attack.mitre.org/techniques/{technique_id}",
                    }
                ],
            }
            objects.append(attack_pattern)

            # Relationship: malware uses attack-pattern
            rel_id = _stix_id("relationship", f"{malware_id}-{ap_id}")
            relationship = {
                "type": "relationship",
                "spec_version": STIX_SPEC_VERSION,
                "id": rel_id,
                "created": now,
                "modified": now,
                "relationship_type": "uses",
                "source_ref": malware_id,
                "target_ref": ap_id,
                "created_by_ref": self._identity_id,
            }
            objects.append(relationship)

        # 5. Relationship: indicator indicates malware
        rel_indicates_id = _stix_id("relationship", f"{indicator_id}-indicates-{malware_id}")
        rel_indicates = {
            "type": "relationship",
            "spec_version": STIX_SPEC_VERSION,
            "id": rel_indicates_id,
            "created": now,
            "modified": now,
            "relationship_type": "indicates",
            "source_ref": indicator_id,
            "target_ref": malware_id,
            "created_by_ref": self._identity_id,
        }
        objects.append(rel_indicates)

        # 6. Sighting (if incident data available)
        if incident:
            sighting_id = _stix_id(
                "sighting",
                incident.get("incident_id", antibody_id),
            )
            sighting = {
                "type": "sighting",
                "spec_version": STIX_SPEC_VERSION,
                "id": sighting_id,
                "created": now,
                "modified": now,
                "first_seen": incident.get("created_at", now),
                "last_seen": now,
                "count": 1,
                "sighting_of_ref": indicator_id,
                "where_sighted_refs": [self._identity_id],
                "created_by_ref": self._identity_id,
                "summary": True,
            }
            objects.append(sighting)

        # 7. Note (antibody metadata)
        note_id = _stix_id("note", f"note-{antibody_id}")
        note_content = (
            f"## IMMUNIS Antibody Metadata\n\n"
            f"- **Antibody ID**: {antibody_id}\n"
            f"- **Attack Family**: {attack_family}\n"
            f"- **Strength**: {antibody.get('strength', 0):.0%}\n"
            f"- **Verification**: {antibody.get('verification_status', 'unknown')}\n"
            f"- **Battleground Rounds**: {antibody.get('battleground_rounds', 0)}\n"
            f"- **Red Variants Tested**: {antibody.get('red_variants_tested', 0)}\n"
            f"- **Blue Blocks**: {antibody.get('blue_blocks', 0)}\n"
        )

        if antibody.get("actuarial_expected_loss"):
            note_content += (
                f"- **Expected Loss**: R{antibody['actuarial_expected_loss']:,.0f}\n"
                f"- **VaR(95%)**: R{antibody.get('actuarial_var_95', 0):,.0f}\n"
                f"- **CVaR(95%)**: R{antibody.get('actuarial_cvar_95', 0):,.0f}\n"
            )

        note = {
            "type": "note",
            "spec_version": STIX_SPEC_VERSION,
            "id": note_id,
            "created": now,
            "modified": now,
            "content": note_content,
            "object_refs": [indicator_id, malware_id],
            "created_by_ref": self._identity_id,
        }
        objects.append(note)

        # Build bundle
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": objects,
        }

        self._export_count += 1

        logger.info(
            f"STIX bundle exported: {antibody_id}, "
            f"{len(objects)} objects, "
            f"{len(mitre_techniques)} ATT&CK techniques"
        )

        return bundle

    def _build_stix_pattern(
        self,
        detection_rule: dict,
        indicators: list,
    ) -> str:
        """
        Build a STIX 2.1 pattern from an antibody detection rule.

        STIX patterns use a specific syntax:
          [email-message:subject = 'urgent'] AND [email-message:body_multipart[0].body_raw_ref.name MATCHES 'invoice']
        """
        parts = []

        # Build from indicators (string patterns)
        for indicator in indicators[:10]:  # Limit to 10 for pattern size
            if isinstance(indicator, str) and indicator.strip():
                # Escape single quotes
                escaped = indicator.replace("'", "\\'")
                parts.append(
                    f"[email-message:body_multipart[*].body_raw_ref.name MATCHES '{escaped}']"
                )

        # Build from thresholds
        thresholds = detection_rule.get("thresholds", {})
        for feature, threshold in list(thresholds.items())[:5]:
            if isinstance(threshold, (int, float)):
                parts.append(
                    f"[x-immunis-feature:{feature} >= {threshold}]"
                )

        if not parts:
            # Fallback pattern
            family = detection_rule.get("family", "unknown")
            parts.append(
                f"[x-immunis-detection:family = '{family}']"
            )

        logic = detection_rule.get("logic", "AND")
        joiner = " AND " if logic == "AND" else " OR "

        return joiner.join(parts)

    def export_bulk(
        self,
        antibodies: list[dict],
        incidents: Optional[list[dict]] = None,
    ) -> dict:
        """Export multiple antibodies as a single STIX bundle."""
        all_objects = []
        incidents_map = {}

        if incidents:
            for inc in incidents:
                inc_id = inc.get("incident_id", "")
                if inc_id:
                    incidents_map[inc_id] = inc

        for antibody in antibodies:
            incident = incidents_map.get(
                antibody.get("source_incident_id"), None
            )
            bundle = self.export_antibody(antibody, incident)
            all_objects.extend(bundle.get("objects", []))

        # Deduplicate by ID
        seen_ids = set()
        unique_objects = []
        for obj in all_objects:
            obj_id = obj.get("id", "")
            if obj_id not in seen_ids:
                seen_ids.add(obj_id)
                unique_objects.append(obj)

        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": unique_objects,
        }

    def get_stats(self) -> dict:
        return {
            "total_exports": self._export_count,
            "stix_version": STIX_SPEC_VERSION,
            "mitre_techniques_mapped": len(self.MITRE_REFERENCES),
        }


class TAXIIServer:
    """
    TAXII 2.1 server for serving STIX bundles.

    Provides standard TAXII endpoints that can be mounted
    on the FastAPI application.

    Collections:
    1. immunis-antibodies — all promoted antibodies
    2. immunis-incidents — all detected incidents
    3. immunis-indicators — detection rules only
    """

    def __init__(self):
        self._collections: dict[str, STIXCollection] = {}
        self._exporter = STIXExporter()

        # Create default collections
        self._collections["immunis-antibodies"] = STIXCollection(
            collection_id="immunis-antibodies",
            title="IMMUNIS Antibodies",
            description=(
                "Adversarially-tested, formally-verified detection rules "
                "from the IMMUNIS ACIN immune network."
            ),
            can_read=True,
            can_write=False,
        )

        self._collections["immunis-incidents"] = STIXCollection(
            collection_id="immunis-incidents",
            title="IMMUNIS Incidents",
            description="Threat incidents detected by IMMUNIS ACIN.",
            can_read=True,
            can_write=False,
        )

        self._collections["immunis-community"] = STIXCollection(
            collection_id="immunis-community",
            title="IMMUNIS Community Feed",
            description=(
                "Community-contributed threat intelligence. "
                "Accepts STIX bundles from external sources."
            ),
            can_read=True,
            can_write=True,
        )

        logger.info(
            f"TAXII server initialised: {len(self._collections)} collections"
        )

    @property
    def exporter(self) -> STIXExporter:
        return self._exporter

    def get_discovery(self) -> dict:
        """TAXII Discovery endpoint response."""
        return {
            "title": "IMMUNIS ACIN TAXII Server",
            "description": (
                "Threat intelligence from the IMMUNIS Adversarial "
                "Coevolutionary Immune Network"
            ),
            "contact": "immunis-acin@security.local",
            "default": "/taxii2/",
            "api_roots": ["/taxii2/"],
        }

    def get_api_root(self) -> dict:
        """TAXII API Root endpoint response."""
        return {
            "title": "IMMUNIS ACIN",
            "description": "IMMUNIS threat intelligence API root",
            "versions": [TAXII_VERSION],
            "max_content_length": 10 * 1024 * 1024,  # MB
        }

    def get_collections(self) -> dict:
        """List all TAXII collections."""
        return {
            "collections": [
                col.to_taxii_dict()
                for col in self._collections.values()
            ]
        }

    def get_collection(self, collection_id: str) -> Optional[dict]:
        """Get a specific collection."""
        col = self._collections.get(collection_id)
        if col is None:
            return None
        return col.to_taxii_dict()

    def get_objects(
        self,
        collection_id: str,
        added_after: Optional[str] = None,
        object_type: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Optional[dict]:
        """
        Get STIX objects from a collection.

        Supports filtering by:
        - added_after: ISO timestamp
        - object_type: STIX object type (indicator, malware, etc.)
        - limit/offset: pagination
        """
        col = self._collections.get(collection_id)
        if col is None:
            return None

        objects = col.objects

        # Filter by added_after
        if added_after:
            objects = [
                obj for obj in objects
                if obj.get("created", "") > added_after
            ]

        # Filter by type
        if object_type:
            objects = [
                obj for obj in objects
                if obj.get("type") == object_type
            ]

        # Paginate
        total = len(objects)
        objects = objects[offset:offset + limit]

        return {
            "type": "bundle",
            "id": f"bundle--{__import__('uuid').uuid4()}",
            "objects": objects,
            "x_taxii_more": (offset + limit) < total,
            "x_taxii_total": total,
        }

    def add_objects(
        self,
        collection_id: str,
        bundle: dict,
    ) -> Optional[dict]:
        """
        Add STIX objects to a writable collection.

        Returns status dict with accepted/rejected counts.
        """
        col = self._collections.get(collection_id)
        if col is None:
            return None

        if not col.can_write:
            return {
                "status": "error",
                "message": f"Collection {collection_id} is read-only",
            }

        objects = bundle.get("objects", [])
        accepted = 0
        rejected = 0

        # Deduplicate by ID
        existing_ids = {obj.get("id") for obj in col.objects}

        for obj in objects:
            obj_id = obj.get("id", "")
            obj_type = obj.get("type", "")

            # Validate basic STIX structure
            if not obj_id or not obj_type:
                rejected += 1
                continue

            if obj_id in existing_ids:
                rejected += 1
                continue

            # Validate spec_version
            if obj.get("spec_version") and obj["spec_version"] != STIX_SPEC_VERSION:
                rejected += 1
                continue

            col.objects.append(obj)
            existing_ids.add(obj_id)
            accepted += 1

        logger.info(
            f"TAXII add to {collection_id}: "
            f"{accepted} accepted, {rejected} rejected"
        )

        return {
            "status": "complete",
            "total_count": len(objects),
            "success_count": accepted,
            "failure_count": rejected,
        }

    def add_antibody_to_collection(
        self,
        antibody: dict,
        incident: Optional[dict] = None,
        collection_id: str = "immunis-antibodies",
    ) -> bool:
        """
        Export an antibody and add it to a collection.

        Convenience method that combines export + add.
        """
        col = self._collections.get(collection_id)
        if col is None:
            return False

        bundle = self._exporter.export_antibody(antibody, incident)
        objects = bundle.get("objects", [])

        existing_ids = {obj.get("id") for obj in col.objects}
        added = 0

        for obj in objects:
            obj_id = obj.get("id", "")
            if obj_id and obj_id not in existing_ids:
                col.objects.append(obj)
                existing_ids.add(obj_id)
                added += 1

        logger.debug(
            f"Added {added} STIX objects for antibody "
            f"{antibody.get('antibody_id')} to {collection_id}"
        )

        return added > 0

    def refresh_from_database(self) -> int:
        """
        Refresh collections from the database.

        Loads all promoted antibodies and recent incidents,
        exports them as STIX, and populates the collections.

        Returns number of objects added.
        """
        try:
            from backend.storage.database import get_database
            db = get_database()

            # Load promoted antibodies
            antibodies = db.query_antibodies(status="promoted", limit=1000)

            # Load recent incidents
            incidents = db.query_incidents(limit=1000)
            incidents_map = {
                inc.get("incident_id", ""): inc
                for inc in incidents
            }

            total_added = 0

            for antibody in antibodies:
                incident = incidents_map.get(
                    antibody.get("source_incident_id"), None
                )
                if self.add_antibody_to_collection(antibody, incident):
                    total_added += 1

            logger.info(
                f"TAXII collections refreshed: {total_added} antibodies exported"
            )

            return total_added

        except Exception as e:
            logger.error(f"Failed to refresh TAXII collections: {e}")
            return 0

    def get_stats(self) -> dict:
        """Return TAXII server statistics."""
        collection_stats = {}
        for col_id, col in self._collections.items():
            type_counts = {}
            for obj in col.objects:
                obj_type = obj.get("type", "unknown")
                type_counts[obj_type] = type_counts.get(obj_type, 0) + 1

            collection_stats[col_id] = {
                "total_objects": len(col.objects),
                "can_read": col.can_read,
                "can_write": col.can_write,
                "object_types": type_counts,
            }

        return {
            "taxii_version": TAXII_VERSION,
            "stix_version": STIX_SPEC_VERSION,
            "collections": collection_stats,
            "exporter_stats": self._exporter.get_stats(),
        }


# Module-level singletons
_exporter: Optional[STIXExporter] = None
_taxii_server: Optional[TAXIIServer] = None


def get_stix_exporter() -> STIXExporter:
    """Get or create the singleton STIXExporter instance."""
    global _exporter
    if _exporter is None:
        _exporter = STIXExporter()
    return _exporter


def get_taxii_server() -> TAXIIServer:
    """Get or create the singleton TAXIIServer instance."""
    global _taxii_server
    if _taxii_server is None:
        _taxii_server = TAXIIServer()
    return _taxii_server
