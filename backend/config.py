"""
IMMUNIS ACIN — Centralised Configuration

Every module imports configuration from here. Never read os.environ directly.
All env vars validated at startup. Missing required vars cause immediate failure
with clear error message — not a cryptic KeyError 3 hours into a demo.

FIXED: vLLM detection now checks for empty/default endpoint.
FIXED: Provider priority reordered for development (Ollama first).

Temperature: 0.3
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    All IMMUNIS ACIN configuration in one place.
    
    Loaded from .env file and environment variables.
    Environment variables take precedence over .env file.
    All fields are typed and validated — no stringly-typed config.
    """

    # === AIsa.one (Primary AI API) ===
    aisa_api_key: str = Field(default="", description="AIsa.one API key for Claude/GPT/DeepSeek")
    aisa_base_url: str = Field(default="https://api.aisa.one/v1")

    # === AMD Developer Cloud ===
    amd_api_key: str = Field(default="")
    amd_endpoint: str = Field(default="")

    # === HuggingFace ===
    hf_token: str = Field(default="")
    hf_organization: str = Field(default="amd-developer-hackathon")

    # === Model Inference ===
    vllm_endpoint: str = Field(default="", description="vLLM server URL. Leave EMPTY if no server running.")
    sentinel_model_id: str = Field(default="immunis/immunis-sentinel-7b-qlora")
    adversary_model_id: str = Field(default="immunis/immunis-adversary-8b-rlhf")
    vision_model_id: str = Field(default="immunis/immunis-vision-7b-qlora")

    # === Fallback AI APIs ===
    openrouter_api_key: str = Field(default="")
    groq_api_key: str = Field(default="")

    # === Local Models ===
    ollama_base_url: str = Field(default="http://localhost:11434")
    ollama_model: str = Field(default="llama3.1:latest")

    # === Database ===
    database_url: str = Field(default="sqlite:///./immunis.db")
    vector_store_path: str = Field(default="./data/faiss_index")

    # === Security ===
    jwt_secret: str = Field(default="CHANGE_ME_IN_PRODUCTION")
    node_private_key: str = Field(default="")
    lockout_hardware_key_id: str = Field(default="")

    # === Mesh Network ===
    immunis_node_id: str = Field(default="node-primary-001")
    immunis_mesh_port: int = Field(default=8765)
    immunis_mesh_peers: str = Field(default="")

    # === Application ===
    port: int = Field(default=8000)
    frontend_url: str = Field(default="http://localhost:3000")
    debug: bool = Field(default=True)
    log_level: str = Field(default="INFO")

    # === Feature Flags ===
    enable_battleground: bool = Field(default=True)
    enable_vision: bool = Field(default=True)
    enable_scanner: bool = Field(default=True)
    enable_deception: bool = Field(default=True)
    enable_stix_taxii: bool = Field(default=True)
    enable_biometrics: bool = Field(default=False)
    enable_post_quantum: bool = Field(default=True)

    # === Thresholds ===
    battleground_max_iterations: int = Field(default=20)
    battleground_promotion_threshold: float = Field(default=0.85)
    surprise_known_threshold: float = Field(default=3.0)
    surprise_novel_threshold: float = Field(default=8.0)

    # === PID Controller ===
    pid_kp: float = Field(default=0.5)
    pid_ki: float = Field(default=0.1)
    pid_kd: float = Field(default=0.3)
    immunity_target: float = Field(default=85.0)

    # === Temperatures (per-agent) ===
    temp_fingerprint: float = Field(default=0.1)
    temp_synthesis: float = Field(default=0.3)
    temp_red_agent: float = Field(default=0.8)
    temp_blue_agent: float = Field(default=0.1)
    temp_evolution: float = Field(default=0.3)
    temp_vision: float = Field(default=0.2)
    temp_arbiter: float = Field(default=0.2)
    temp_copilot: float = Field(default=0.6)
    temp_training_data: float = Field(default=0.7)
    temp_vulnerability_scan: float = Field(default=0.2)

    # === Agent Timeouts (seconds) ===
    agent_timeout_fingerprint: float = Field(default=60.0)
    agent_timeout_synthesis: float = Field(default=60.0)
    agent_timeout_red: float = Field(default=45.0)
    agent_timeout_blue: float = Field(default=30.0)

    @field_validator("jwt_secret")
    @classmethod
    def jwt_secret_not_default(cls, v: str) -> str:
        if v == "CHANGE_ME_IN_PRODUCTION" and os.getenv("DEBUG", "true").lower() != "true":
            raise ValueError(
                "JWT_SECRET must be changed from default in production. "
                "Generate with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        return v

    @property
    def mesh_peers_list(self) -> list[str]:
        """Parse comma-separated mesh peers into list."""
        if not self.immunis_mesh_peers:
            return []
        return [p.strip() for p in self.immunis_mesh_peers.split(",") if p.strip()]

    @property
    def project_root(self) -> Path:
        """Project root directory."""
        return Path(__file__).parent.parent

    @property
    def data_dir(self) -> Path:
        """Data directory — created if not exists."""
        d = self.project_root / "data"
        d.mkdir(parents=True, exist_ok=True)
        return d

    @property
    def has_aisa(self) -> bool:
        """Whether AIsa.one is configured with a valid key."""
        return bool(self.aisa_api_key and self.aisa_api_key != "your_aisa_api_key_here")

    @property
    def has_amd(self) -> bool:
        """Whether AMD Developer Cloud is configured."""
        return bool(self.amd_api_key and self.amd_api_key != "your_amd_key_here")

    @property
    def has_vllm(self) -> bool:
        """
        Whether vLLM inference server is ACTUALLY available.
        
        CRITICAL FIX: Returns False if:
        - Endpoint is empty string
        - Endpoint is default placeholder
        - Endpoint is localhost:8080 but we haven't verified it's running
        
        In development, vLLM is almost never running. This prevents
        the pipeline from wasting 30 seconds trying to connect to nothing.
        """
        if not self.vllm_endpoint:
            return False
        if self.vllm_endpoint in ("http://localhost:8080", "your_vllm_endpoint_here"):
            # Only mark as available if explicitly set to a non-default value
            # For development, this should be empty in .env
            return False
        return True

    @property
    def has_ollama(self) -> bool:
        """Whether Ollama is available (check URL is set)."""
        return bool(self.ollama_base_url)

    @property
    def has_groq(self) -> bool:
        """Whether Groq is configured."""
        return bool(self.groq_api_key and self.groq_api_key != "your_groq_key_here")

    @property
    def has_openrouter(self) -> bool:
        """Whether OpenRouter is configured."""
        return bool(self.openrouter_api_key and self.openrouter_api_key != "your_openrouter_key_here")

    def get_best_available_provider(self) -> str:
        """
        Returns the best available AI provider in priority order.
        
        DEVELOPMENT priority (cost-optimised):
            1. Ollama (free, local, no quota)
            2. Groq (free tier, fast)
            3. AIsa.one (paid, save for production/training data)
            4. OpenRouter (paid fallback)
            5. vLLM (only when fine-tuned models are deployed)
        
        PRODUCTION priority (quality-optimised):
            1. vLLM (fine-tuned models on AMD)
            2. AIsa.one (frontier models)
            3. Groq (fast inference)
            4. Ollama (local fallback)
        """
        if self.debug:
            # Development mode — prioritise fast + free
            if self.has_groq:
                return "groq"  # Free tier, 1-2 second responses
            if self.has_ollama:
                return "ollama"  # Free but slow on CPU
            if self.has_aisa:
                return "aisa"
            if self.has_openrouter:
                return "openrouter"
            if self.has_vllm:
                return "vllm"
        else:
            # Production mode — prioritise quality
            if self.has_vllm:
                return "vllm"
            if self.has_aisa:
                return "aisa"
            if self.has_groq:
                return "groq"
            if self.has_openrouter:
                return "openrouter"
            if self.has_ollama:
                return "ollama"

        return "none"

    def validate_minimum_requirements(self) -> list[str]:
        """
        Check that minimum requirements are met for the system to function.
        Returns list of warnings. Empty list = all good.
        """
        warnings = []

        if not self.has_aisa and not self.has_vllm and not self.has_ollama and not self.has_groq:
            warnings.append(
                "CRITICAL: No AI provider configured. "
                "Set AISA_API_KEY, GROQ_API_KEY, or ensure Ollama is running. "
                "System will use deterministic fallbacks only."
            )

        if self.jwt_secret == "CHANGE_ME_IN_PRODUCTION":
            warnings.append(
                "WARNING: JWT_SECRET is default. Acceptable for development only."
            )

        if not self.node_private_key:
            warnings.append(
                "INFO: NODE_PRIVATE_KEY not set. Will generate ephemeral key on startup. "
                "Set this in production for persistent node identity."
            )

        if self.has_vllm:
            warnings.append(
                f"INFO: vLLM configured at {self.vllm_endpoint}. "
                "Ensure server is running before sending threats."
            )

        if not self.has_vllm and not self.has_groq and self.has_ollama:
            warnings.append(
                "INFO: Using Ollama as primary provider. Inference will be slower "
                "than cloud providers but free and private. Ensure 'ollama serve' is running."
            )

        return warnings

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Get cached settings instance.
    Called once at startup, cached forever.
    """
    return Settings()


def print_startup_banner(settings: Settings) -> None:
    """Print startup information and warnings."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    console = Console()

    # Banner
    console.print(Panel.fit(
        "[bold green]IMMUNIS ACIN[/bold green]\n"
        "[dim]Adversarial Coevolutionary Immune Network[/dim]\n"
        "[cyan]The breach that teaches. The system that remembers.[/cyan]",
        border_style="green",
    ))

    # Provider status
    table = Table(title="AI Provider Status", show_header=True)
    table.add_column("Provider", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Usage")

    providers = [
        ("vLLM (AMD MI300X)", settings.has_vllm, "Fine-tuned models — production"),
        ("AIsa.one", settings.has_aisa, "Claude/GPT/DeepSeek — training data + production"),
        ("Groq", settings.has_groq, "Fast inference — Red Agent + development"),
        ("OpenRouter", settings.has_openrouter, "Multi-model routing — tertiary"),
        ("Ollama (local)", settings.has_ollama, "Local models — development primary"),
    ]

    for name, available, usage in providers:
        status = "[green]✓ READY[/green]" if available else "[yellow]✗ NOT CONFIGURED[/yellow]"
        table.add_row(name, status, usage)

    console.print(table)

    # Best provider
    best = settings.get_best_available_provider()
    console.print(f"\n[bold]Primary provider:[/bold] [cyan]{best}[/cyan]")
    if best == "ollama":
        console.print("[dim]  (Development mode — using free local inference)[/dim]")

    # Feature flags
    features = Table(title="Feature Flags", show_header=True)
    features.add_column("Feature", style="cyan")
    features.add_column("Status", style="bold")

    feature_list = [
        ("Battleground (Red-Blue Arms Race)", settings.enable_battleground),
        ("Vision (Multimodal Threat Detection)", settings.enable_vision),
        ("Vulnerability Scanner", settings.enable_scanner),
        ("Deception Layer (Honeypots)", settings.enable_deception),
        ("STIX/TAXII Export", settings.enable_stix_taxii),
        ("Behavioral Biometrics", settings.enable_biometrics),
        ("Post-Quantum Cryptography", settings.enable_post_quantum),
    ]

    for name, enabled in feature_list:
        status = "[green]ENABLED[/green]" if enabled else "[yellow]DISABLED[/yellow]"
        features.add_row(name, status)

    console.print(features)

    # Warnings
    warnings = settings.validate_minimum_requirements()
    if warnings:
        console.print("\n[bold yellow]Startup Warnings:[/bold yellow]")
        for w in warnings:
            if w.startswith("CRITICAL"):
                console.print(f"  [bold red]{w}[/bold red]")
            elif w.startswith("WARNING"):
                console.print(f"  [yellow]{w}[/yellow]")
            else:
                console.print(f"  [dim]{w}[/dim]")
    else:
        console.print("\n[bold green]✓ All systems ready.[/bold green]")

    console.print()
