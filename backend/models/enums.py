"""
IMMUNIS ACIN — Enumerations

Single source of truth for all enumerated types.
Every enum used anywhere in the system is defined HERE and imported from here.
No enum is ever defined inline in another file.

Why centralised enums matter:
- Agent 1 outputs attack_type. Agent 5 classifies against attack_type. 
  If they use different enum values, the pipeline silently fails.
- Centralisation makes this impossible.

Temperature: 0.3 (enums are data definitions, not creative work)
"""

from __future__ import annotations

from enum import Enum, unique


# === THREAT CLASSIFICATION ===

@unique
class AttackType(str, Enum):
    """Classification of attack type. Used by Agent 1 and Agent 5."""
    BEC = "BEC"
    PHISHING = "Phishing"
    SPEARPHISHING = "Spearphishing"
    VISHING = "Vishing"
    RANSOMWARE = "Ransomware"
    CREDENTIAL_HARVESTING = "CredentialHarvesting"
    INVOICE_FRAUD = "InvoiceFraud"
    CEO_FRAUD = "CEOFraud"
    VENDOR_IMPERSONATION = "VendorImpersonation"
    IT_SUPPORT_IMPERSONATION = "ITSupportImpersonation"
    GOVERNMENT_IMPERSONATION = "GovernmentImpersonation"
    INSIDER_THREAT = "InsiderThreat"
    NETWORK_INTRUSION = "NetworkIntrusion"
    MALWARE = "Malware"
    APT = "APT"
    QR_PHISHING = "QRPhishing"
    DEEPFAKE = "Deepfake"
    DOCUMENT_FORGERY = "DocumentForgery"
    STEGANOGRAPHY = "Steganography"
    BENIGN = "Benign"
    OTHER = "Other"

    @classmethod
    def from_string(cls, value: str) -> "AttackType":
        """
        Soft normalisation — LLMs return inconsistent casing.
        'bec' → BEC, 'phishing' → Phishing, 'unknown_thing' → Other
        """
        lookup = {item.value.lower(): item for item in cls}
        lookup.update({item.name.lower(): item for item in cls})
        # Common LLM variations
        lookup["business_email_compromise"] = cls.BEC
        lookup["business email compromise"] = cls.BEC
        lookup["spear_phishing"] = cls.SPEARPHISHING
        lookup["spear phishing"] = cls.SPEARPHISHING
        lookup["voice_phishing"] = cls.VISHING
        lookup["ransomware_initial_access"] = cls.RANSOMWARE
        lookup["credential_harvest"] = cls.CREDENTIAL_HARVESTING
        lookup["qr_code_phishing"] = cls.QR_PHISHING
        lookup["quishing"] = cls.QR_PHISHING
        lookup["deep_fake"] = cls.DEEPFAKE

        return lookup.get(value.lower().strip(), cls.OTHER)


@unique
class ThreatVerdict(str, Enum):
    """Classification verdict from Agent 5 (Variant Recogniser)."""
    KNOWN = "known"       # Exact antibody match — instant block
    VARIANT = "variant"   # Related to known pattern — bridge + learn
    NOVEL = "novel"       # Never seen — full AIR protocol
    BENIGN = "benign"     # Legitimate communication


@unique
class SurpriseLevel(str, Enum):
    """Information-theoretic surprise classification."""
    EXPECTED = "expected"           # S < 3 bits — known pattern
    MODERATE = "moderate"           # 3 ≤ S < 8 bits — variant
    HIGHLY_SURPRISING = "novel"     # S ≥ 8 bits — genuinely novel


@unique
class Severity(str, Enum):
    """Threat severity. Maps to response urgency."""
    CRITICAL = "Critical"   # Immediate automated response
    HIGH = "High"           # Automated response + SOC alert
    MEDIUM = "Medium"       # SOC review queue
    LOW = "Low"             # Log and monitor
    INFO = "Info"           # Informational only


@unique
class AntibodyStatus(str, Enum):
    """Lifecycle status of an antibody."""
    PENDING = "pending"                   # Just synthesised, not tested
    TESTING = "testing"                   # In Battleground stress test
    VALIDATED = "validated"               # Passed Arbiter threshold
    PROMOTED = "promoted"                 # In production library
    BROADCAST = "broadcast"               # Sent to mesh
    DEPRECATED = "deprecated"             # Superseded by stronger antibody
    FAILED = "failed"                     # Could not reach strength threshold


# === MITRE ATT&CK ===

@unique
class MitrePhase(str, Enum):
    """MITRE ATT&CK kill chain phases."""
    RECONNAISSANCE = "Reconnaissance"
    RESOURCE_DEVELOPMENT = "ResourceDevelopment"
    INITIAL_ACCESS = "InitialAccess"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "PrivilegeEscalation"
    DEFENSE_EVASION = "DefenseEvasion"
    CREDENTIAL_ACCESS = "CredentialAccess"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "LateralMovement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "CommandAndControl"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"

    @classmethod
    def from_string(cls, value: str) -> "MitrePhase":
        lookup = {item.value.lower(): item for item in cls}
        lookup.update({item.name.lower(): item for item in cls})
        # Common LLM variations
        lookup["initial_access"] = cls.INITIAL_ACCESS
        lookup["initial access"] = cls.INITIAL_ACCESS
        lookup["privilege_escalation"] = cls.PRIVILEGE_ESCALATION
        lookup["lateral_movement"] = cls.LATERAL_MOVEMENT
        lookup["command_and_control"] = cls.COMMAND_AND_CONTROL
        lookup["c2"] = cls.COMMAND_AND_CONTROL
        lookup["defense_evasion"] = cls.DEFENSE_EVASION
        return lookup.get(value.lower().strip().replace(" ", "_"), cls.INITIAL_ACCESS)


# === MANIPULATION TECHNIQUES ===

@unique
class ManipulationTechnique(str, Enum):
    """Psychological manipulation technique used in social engineering."""
    AUTHORITY = "Authority"             # Impersonating authority figure
    URGENCY = "Urgency"                 # Creating time pressure
    SCARCITY = "Scarcity"               # Limited availability
    SOCIAL_PROOF = "SocialProof"        # Others are doing it
    RECIPROCITY = "Reciprocity"         # I did something for you
    FEAR = "Fear"                       # Threatening consequences
    GREED = "Greed"                     # Promising reward
    CURIOSITY = "Curiosity"             # Enticing with information
    TRUST_EXPLOITATION = "Trust"        # Exploiting existing relationship
    INTIMIDATION = "Intimidation"       # Direct threat
    NONE = "None"                       # No manipulation detected (benign)

    @classmethod
    def from_string(cls, value: str) -> "ManipulationTechnique":
        lookup = {item.value.lower(): item for item in cls}
        lookup.update({item.name.lower(): item for item in cls})
        lookup["social_proof"] = cls.SOCIAL_PROOF
        lookup["trust_exploitation"] = cls.TRUST_EXPLOITATION
        return lookup.get(value.lower().strip(), cls.NONE)


# === LANGUAGES ===

@unique
class Language(str, Enum):
    """Supported languages for threat detection."""
    # South African
    ENGLISH = "en"
    ISIZULU = "zu"
    SESOTHO = "st"
    AFRIKAANS = "af"
    ISIXHOSA = "xh"
    SEPEDI = "nso"
    SETSWANA = "tn"
    # MENA
    ARABIC = "ar"
    FARSI = "fa"
    TURKISH = "tr"
    HEBREW = "he"
    URDU = "ur"
    # APAC
    MANDARIN = "zh"
    HINDI = "hi"
    BAHASA_INDONESIA = "id"
    BAHASA_MELAYU = "ms"
    JAPANESE = "ja"
    KOREAN = "ko"
    THAI = "th"
    VIETNAMESE = "vi"
    TAGALOG = "tl"
    # European
    FRENCH = "fr"
    GERMAN = "de"
    SPANISH = "es"
    ITALIAN = "it"
    PORTUGUESE = "pt"
    DUTCH = "nl"
    POLISH = "pl"
    ROMANIAN = "ro"
    SWEDISH = "sv"
    NORWEGIAN = "no"
    DANISH = "da"
    FINNISH = "fi"
    # African
    YORUBA = "yo"
    IGBO = "ig"
    HAUSA = "ha"
    SWAHILI = "sw"
    AMHARIC = "am"
    # Mixed/Unknown
    MIXED = "mixed"
    UNKNOWN = "unknown"

    @classmethod
    def from_string(cls, value: str) -> "Language":
        lookup = {item.value.lower(): item for item in cls}
        lookup.update({item.name.lower(): item for item in cls})
        # Common names
        lookup["sesotho"] = cls.SESOTHO
        lookup["isizulu"] = cls.ISIZULU
        lookup["isixhosa"] = cls.ISIXHOSA
        lookup["chinese"] = cls.MANDARIN
        lookup["indonesian"] = cls.BAHASA_INDONESIA
        lookup["malay"] = cls.BAHASA_MELAYU
        lookup["brazilian_portuguese"] = cls.PORTUGUESE
        return lookup.get(value.lower().strip(), cls.UNKNOWN)


# === THREAT ACTOR TYPES ===

@unique
class ThreatActorType(str, Enum):
    """Psychographic attacker typology."""
    TYPE_1_LOCAL = "LocalCriminal"         # SA BEC/vishing, hours patience
    TYPE_2_HACKTIVIST = "Hacktivist"       # Ideological, days-weeks
    TYPE_3_RANSOMWARE = "RansomwareGroup"  # Organised crime, weeks
    TYPE_4_APT = "NationStateAPT"          # State-sponsored, months
    TYPE_5_INSIDER = "InsiderThreat"       # Internal, variable
    UNKNOWN = "Unknown"


# === THREAT VECTORS ===

@unique
class ThreatVector(str, Enum):
    """How the threat arrives."""
    EMAIL = "email"
    VOICE = "voice"
    NETWORK = "network"
    ENDPOINT = "endpoint"
    IMAGE = "image"
    DOCUMENT = "document"
    QR_CODE = "qr_code"
    VIDEO = "video"
    URL = "url"
    API = "api"
    SMS = "sms"
    WHATSAPP = "whatsapp"
    UNKNOWN = "unknown"


# === VISUAL THREAT TYPES ===

@unique
class VisualThreatType(str, Enum):
    """Visual threat categories for Agent 8."""
    PHISHING_PAGE = "PhishingPage"
    DOCUMENT_FORGERY = "DocumentForgery"
    MALICIOUS_QR = "MaliciousQR"
    DEEPFAKE = "Deepfake"
    STEGANOGRAPHY = "Steganography"
    BENIGN = "Benign"


# === CONTAINMENT ACTIONS ===

@unique
class ContainmentAction(str, Enum):
    """Actions the polymorphic containment engine can take."""
    QUARANTINE_EMAIL = "quarantine_email"
    BLOCK_SENDER_DOMAIN = "block_sender_domain"
    BLOCK_SOURCE_IP = "block_source_ip"
    ISOLATE_ENDPOINT = "isolate_endpoint"
    SEVER_LATERAL_PATH = "sever_lateral_path"
    RATE_LIMIT_SOURCE = "rate_limit_source"
    ROTATE_CREDENTIALS = "rotate_credentials"
    TERMINATE_SESSIONS = "terminate_sessions"
    DNS_SINKHOLE = "dns_sinkhole"
    REDIRECT_TO_HONEYPOT = "redirect_to_honeypot"
    ALERT_SOC = "alert_soc"
    ALERT_FINANCE = "alert_finance"
    PRESERVE_FORENSICS = "preserve_forensics"


# === COMPLIANCE FRAMEWORKS ===

@unique
class ComplianceFramework(str, Enum):
    """Regulatory and security frameworks IMMUNIS maps to."""
    POPIA = "POPIA"
    CYBERCRIMES_ACT = "CybercrimesAct"
    NCPF = "NCPF"
    NIST_CSF = "NIST_CSF"
    MITRE_ATTACK = "MITRE_ATT&CK"
    ISO_27001 = "ISO27001"
    GDPR = "GDPR"
    SOC2 = "SOC2"
    PCI_DSS = "PCI_DSS"
    SWIFT_CSP = "SWIFT_CSP"
    CIS_BENCHMARKS = "CIS"


# === PIPELINE EVENTS ===

@unique
class PipelineStage(str, Enum):
    """Stages in the 7-stage AIR pipeline. Used for audit trail and WebSocket events."""
    RECEIVED = "received"
    SURPRISE_DETECTION = "surprise_detection"
    CONTAINMENT = "containment"
    DECEPTION = "deception"
    BRIDGE_DEFENSE = "bridge_defense"
    FINGERPRINT = "fingerprint"
    VISUAL_ANALYSIS = "visual_analysis"
    MULTIMODAL_FUSION = "multimodal_fusion"
    ANTIBODY_SYNTHESIS = "antibody_synthesis"
    FORMAL_VERIFICATION = "formal_verification"
    COMPLIANCE_MAPPING = "compliance_mapping"
    TAF_UPDATE = "taf_update"
    BATTLEGROUND_ENTRY = "battleground_entry"
    RED_ATTACK = "red_attack"
    BLUE_DEFENSE = "blue_defense"
    ARBITER_DECISION = "arbiter_decision"
    MESH_BROADCAST = "mesh_broadcast"
    STIX_EXPORT = "stix_export"
    RESPONSE_GENERATED = "response_generated"
    PIPELINE_COMPLETE = "pipeline_complete"
    PIPELINE_FAILED = "pipeline_failed"


# === AI PROVIDERS ===

@unique
class AIProvider(str, Enum):
    """AI inference providers in priority order."""
    VLLM = "vllm"              # Fine-tuned models on AMD MI300X
    AISA = "aisa"              # AIsa.one (Claude, GPT, DeepSeek)
    GROQ = "groq"              # Groq (fast inference)
    OPENROUTER = "openrouter"  # Multi-model routing
    OLLAMA = "ollama"          # Local models
    DETERMINISTIC = "deterministic"  # No AI — rule-based fallback


# === MESH EVENTS ===

@unique
class MeshEventType(str, Enum):
    """Events on the antibody mesh network."""
    ANTIBODY_BROADCAST = "antibody_broadcast"
    ANTIBODY_RECEIVED = "antibody_received"
    NODE_JOINED = "node_joined"
    NODE_LEFT = "node_left"
    NODE_QUARANTINED = "node_quarantined"
    LOCKOUT_ALERT = "lockout_alert"
    ANTI_ENTROPY_SYNC = "anti_entropy_sync"
    TRUST_SCORE_UPDATE = "trust_score_update"


# === VULNERABILITY SEVERITY ===

@unique
class VulnerabilitySeverity(str, Enum):
    """CVSS-aligned vulnerability severity."""
    CRITICAL = "Critical"   # CVSS 9.0-10.0
    HIGH = "High"           # CVSS 7.0-8.9
    MEDIUM = "Medium"       # CVSS 4.0-6.9
    LOW = "Low"             # CVSS 0.1-3.9
    INFO = "Info"           # Informational
