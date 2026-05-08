"""IMMUNIS ACIN — Model Router

Routes model inference requests to appropriate providers with fallback.
Implements the model routing strategy from IMMUNIS_ACIN.md.
"""

import time
from typing import Optional, Callable, Any
from functools import wraps

from backend.config import settings
from backend.models.enums import AgentID, AIProvider
from backend.models.schemas import ModelInferenceResponse
from backend.services.aisa_client import aisa_client
from backend.security.circuit_breaker import circuit_breaker_registry
from backend.security.rate_limiter import rate_limiter


# Model routing strategy from IMMUNIS_ACIN.md Section 10
ROUTING_STRATEGY = {
    AgentID.INCIDENT_ANALYST: {
        "primary": (AIProvider.VLLM, settings.sentinel_model_id, settings.temp_fingerprint),
        "fallback1": (AIProvider.AISA, "claude-sonnet", settings.temp_fingerprint),
        "fallback2": (AIProvider.OLLAMA, settings.ollama_model, settings.temp_fingerprint),
    },
    AgentID.ANTIBODY_SYNTHESISER: {
        "primary": (AIProvider.VLLM, settings.sentinel_model_id, settings.temp_synthesis),
        "fallback1": (AIProvider.AISA, "gpt-4o", settings.temp_synthesis),
        "fallback2": (AIProvider.OLLAMA, settings.ollama_model, settings.temp_synthesis),
    },
    AgentID.RED_AGENT: {
        "primary": (AIProvider.VLLM, settings.adversary_model_id, settings.temp_red_agent),
        "fallback1": (AIProvider.AISA, "claude-opus", settings.temp_red_agent),
        "fallback2": (AIProvider.GROQ, "llama-3.1-70b", settings.temp_red_agent),
    },
    AgentID.VARIANT_RECOGNISER: {
        "primary": (AIProvider.VLLM, settings.sentinel_model_id, settings.temp_blue_agent),
        "fallback1": (AIProvider.AISA, "gpt-4o", settings.temp_blue_agent),
        "fallback2": (AIProvider.GROQ, "llama-3.1-70b", settings.temp_blue_agent),
    },
    AgentID.EVOLUTION_TRACKER: {
        "primary": (AIProvider.VLLM, "qwen2.5-3b", settings.temp_evolution),
        "fallback1": (AIProvider.AISA, "qwen2.5-3b", settings.temp_evolution),
        "fallback2": None,
    },
    AgentID.VISUAL_ANALYST: {
        "primary": (AIProvider.VLLM, settings.vision_model_id, settings.temp_vision),
        "fallback1": (AIProvider.AISA, "gpt-4o-vision-preview", settings.temp_vision),
        "fallback2": None,
    },
    AgentID.ARBITER: {
        "primary": (AIProvider.VLLM, "qwen2.5-7b", settings.temp_arbiter),
        "fallback1": (AIProvider.AISA, "claude-sonnet", settings.temp_arbiter),
        "fallback2": None,
    },
}


class ModelRouter:
    """
    Routes model inference requests with automatic fallback.

    Implements the routing strategy from IMMUNIS_ACIN.md.
    """

    def __init__(self):
        """Initialise model router"""
        # Provider clients (would be expanded with actual clients)
        self.clients = {
            ModelProvider.AISA: aisa_client,
            # Add other providers as needed
        }

    async def route(
        self,
        agent_id: AgentID,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: int = 1000
    ) -> ModelInferenceResponse:
        """
        Route inference request with fallback.

        Args:
            agent_id: Agent making request
            prompt: User prompt
            system_prompt: Optional system prompt
            temperature: Override temperature from strategy
            max_tokens: Maximum tokens to generate

        Returns:
            ModelInferenceResponse

        Raises:
            Exception: If all providers fail
        """
        strategy = ROUTING_STRATEGY.get(agent_id)
        if not strategy:
            raise ValueError(f"No routing strategy for {agent_id}")

        # Determine temperature
        if temperature is None:
            temperature = strategy["primary"][2]

        last_error = None

        # Try primary
        try:
            return await self._try_provider(
                agent_id,
                strategy["primary"][0],
                strategy["primary"][1],
                prompt,
                system_prompt,
                temperature,
                max_tokens
            )
        except Exception as e:
            last_error = e

        # Try fallback 1
        if strategy["fallback1"]:
            try:
                return await self._try_provider(
                    agent_id,
                    strategy["fallback1"][0],
                    strategy["fallback1"][1],
                    prompt,
                    system_prompt,
                    temperature,
                    max_tokens
                )
            except Exception as e:
                last_error = e

        # Try fallback 2
        if strategy["fallback2"]:
            try:
                return await self._try_provider(
                    agent_id,
                    strategy["fallback2"][0],
                    strategy["fallback2"][1],
                    prompt,
                    system_prompt,
                    temperature,
                    max_tokens
                )
            except Exception as e:
                last_error = e

        # All failed
        raise Exception(f"All providers failed for {agent_id}. Last error: {last_error}")

    async def _try_provider(
        self,
        agent_id: AgentID,
        provider: ModelProvider,
        model: str,
        prompt: str,
        system_prompt: Optional[str],
        temperature: float,
        max_tokens: int
    ) -> ModelInferenceResponse:
        """
        Try inference with specific provider.

        Args:
            agent_id: Agent making request
            provider: Model provider
            model: Model name
            prompt: User prompt
            system_prompt: Optional system prompt
            temperature: Sampling temperature
            max_tokens: Maximum tokens

        Returns:
            ModelInferenceResponse
        """
        # Check rate limiter
        if not rate_limiter.allow_request(
            agent_id=agent_id,
            provider=provider,
            tokens=1
        ):
            wait_time = rate_limiter.get_wait_time(
                agent_id=agent_id,
                provider=provider
            )
            raise Exception(f"Rate limited for {provider}. Wait {wait_time:.2f}s")

        # Check circuit breaker
        breaker = circuit_breaker_registry.get_or_create(agent_id)
        if not breaker.allow_request():
            raise Exception(f"Circuit breaker open for {agent_id}")

        # Route to appropriate client
        if provider == AIProvider.AISA:
            client = self.clients[provider]
            response = await client.inference(
                agent_id=agent_id,
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=temperature,
                max_tokens=max_tokens,
                model=model
            )
            return response
        else:
            # Placeholder for other providers
            # TODO: Implement clients for VLLM, GROQ, OLLAMA, etc.
            raise NotImplementedError(f"Provider {provider} not yet implemented")

    def route_sync(
        self,
        agent_id: AgentID,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: int = 1000
    ) -> ModelInferenceResponse:
        """
        Synchronous route inference request with fallback.

        Args:
            agent_id: Agent making request
            prompt: User prompt
            system_prompt: Optional system prompt
            temperature: Override temperature from strategy
            max_tokens: Maximum tokens to generate

        Returns:
            ModelInferenceResponse

        Raises:
            Exception: If all providers fail
        """
        strategy = ROUTING_STRATEGY.get(agent_id)
        if not strategy:
            raise ValueError(f"No routing strategy for {agent_id}")

        # Determine temperature
        if temperature is None:
            temperature = strategy["primary"][2]

        last_error = None

        # Try primary
        try:
            return self._try_provider_sync(
                agent_id,
                strategy["primary"][0],
                strategy["primary"][1],
                prompt,
                system_prompt,
                temperature,
                max_tokens
            )
        except Exception as e:
            last_error = e

        # Try fallback 1
        if strategy["fallback1"]:
            try:
                return self._try_provider_sync(
                    agent_id,
                    strategy["fallback1"][0],
                    strategy["fallback1"][1],
                    prompt,
                    system_prompt,
                    temperature,
                    max_tokens
                )
            except Exception as e:
                last_error = e

        # Try fallback 2
        if strategy["fallback2"]:
            try:
                return self._try_provider_sync(
                    agent_id,
                    strategy["fallback2"][0],
                    strategy["fallback2"][1],
                    prompt,
                    system_prompt,
                    temperature,
                    max_tokens
                )
            except Exception as e:
                last_error = e

        # All failed
        raise Exception(f"All providers failed for {agent_id}. Last error: {last_error}")

    def _try_provider_sync(
        self,
        agent_id: AgentID,
        provider: AIProvider,
        model: str,
        prompt: str,
        system_prompt: Optional[str],
        temperature: float,
        max_tokens: int
    ) -> ModelInferenceResponse:
        """
        Try synchronous inference with specific provider.

        Args:
            agent_id: Agent making request
            provider: Model provider
            model: Model name
            prompt: User prompt
            system_prompt: Optional system prompt
            temperature: Sampling temperature
            max_tokens: Maximum tokens

        Returns:
            ModelInferenceResponse
        """
        # Check rate limiter
        if not rate_limiter.allow_request(
            agent_id=agent_id,
            provider=provider,
            tokens=1
        ):
            wait_time = rate_limiter.get_wait_time(
                agent_id=agent_id,
                provider=provider
            )
            raise Exception(f"Rate limited for {provider}. Wait {wait_time:.2f}s")

        # Check circuit breaker
        breaker = circuit_breaker_registry.get_or_create(agent_id)
        if not breaker.allow_request():
            raise Exception(f"Circuit breaker open for {agent_id}")

        # Route to appropriate client
        if provider == AIProvider.AISA:
            client = self.clients[provider]
            response = client.inference_sync(
                agent_id=agent_id,
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=temperature,
                max_tokens=max_tokens,
                model=model
            )
            return response
        else:
            # Placeholder for other providers
            raise NotImplementedError(f"Provider {provider} not yet implemented")


# Global router instance
model_router = ModelRouter()
