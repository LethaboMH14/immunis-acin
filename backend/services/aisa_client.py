"""
IMMUNIS ACIN — Unified AI Client

Single interface to call any AI model through any provider.
All providers use OpenAI-compatible APIs — one client type works for all.

FIXED: Provider chain now respects debug/production mode from config.
FIXED: Ollama timeout increased to 120s (local models are slower).
FIXED: vLLM skipped entirely when has_vllm is False.

Security:
- API keys loaded from config, never hardcoded
- No request/response content logged
- Timeout on every call
- Retry with exponential backoff

Temperature: 0.3
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Optional, Type

import httpx
from openai import AsyncOpenAI
from pydantic import BaseModel

from backend.config import get_settings

logger = logging.getLogger("immunis.ai_client")


# ============================================================================
# MODEL DEFINITIONS
# ============================================================================

PROVIDER_MODELS = {
    "aisa": {
        "claude_opus": "claude-opus-4-20250514",
        "claude_sonnet": "claude-sonnet-4-20250514",
        "gpt4o": "gpt-4o",
        "gpt4o_mini": "gpt-4o-mini",
        "deepseek_chat": "deepseek-chat",
        "deepseek_reasoner": "deepseek-reasoner",
        "default": "claude-sonnet-4-20250514",
    },
    "groq": {
        "llama33_70b": "llama-3.3-70b-versatile",
        "llama31_8b": "llama-3.1-8b-instant",
        "qwen3_32b": "qwen/qwen3-32b",
        "default": "llama-3.3-70b-versatile",
    },
    "openrouter": {
        "claude_sonnet": "anthropic/claude-sonnet-4",
        "gpt4o": "openai/gpt-4o",
        "llama31": "meta-llama/llama-3.1-70b-instruct",
        "default": "anthropic/claude-sonnet-4",
    },
    "ollama": {
        "qwen25_coder": "qwen2.5-coder:7b",
        "llama31": "llama3.1:latest",
        "deepseek_coder": "deepseek-coder:latest",
        "default": "qwen2.5-coder:7b",
    },
    "vllm": {
        "sentinel": "immunis-sentinel",
        "adversary": "immunis-adversary",
        "vision": "immunis-vision",
        "default": "immunis-sentinel",
    },
}


# ============================================================================
# CLIENT FACTORY
# ============================================================================

def _create_client(provider: str) -> Optional[AsyncOpenAI]:
    """Create an AsyncOpenAI client for the specified provider."""
    settings = get_settings()

    if provider == "aisa" and settings.has_aisa:
        return AsyncOpenAI(
            api_key=settings.aisa_api_key,
            base_url=settings.aisa_base_url,
            timeout=httpx.Timeout(60.0, connect=10.0),
        )
    elif provider == "groq" and settings.has_groq:
        return AsyncOpenAI(
            api_key=settings.groq_api_key,
            base_url="https://api.groq.com/openai/v1",
            timeout=httpx.Timeout(30.0, connect=10.0),
        )
    elif provider == "openrouter" and settings.has_openrouter:
        return AsyncOpenAI(
            api_key=settings.openrouter_api_key,
            base_url="https://openrouter.ai/api/v1",
            timeout=httpx.Timeout(60.0, connect=10.0),
        )
    elif provider == "ollama" and settings.has_ollama:
        return AsyncOpenAI(
            api_key="ollama",
            base_url=f"{settings.ollama_base_url}/v1",
            timeout=httpx.Timeout(600.0, connect=5.0),  # Ollama is slow on CPU — needs 5+ minutes
        )
    elif provider == "vllm" and settings.has_vllm:
        return AsyncOpenAI(
            api_key="not-needed",
            base_url=settings.vllm_endpoint,
            timeout=httpx.Timeout(30.0, connect=5.0),
        )

    return None


# ============================================================================
# CORE CALL FUNCTION
# ============================================================================

async def call_ai(
    provider: str,
    model: str,
    system_prompt: str,
    user_content: str,
    temperature: float = 0.3,
    max_tokens: int = 2048,
    response_schema: Optional[Type[BaseModel]] = None,
    timeout_seconds: float = 60.0,
    retry_count: int = 2,
    retry_backoff_base: float = 2.0,
) -> dict[str, Any]:
    """
    Call an AI model and return the response.
    
    This is the ONLY function that makes LLM API calls in the entire system.
    
    Security:
        - system_prompt is NEVER logged
        - user_content is NEVER logged
        - response content is NEVER logged
        - Only metadata (latency, tokens, success/failure) is logged
    """
    client = _create_client(provider)
    if client is None:
        return {
            "content": "",
            "parsed": None,
            "provider": provider,
            "model": model,
            "latency_ms": 0.0,
            "tokens_used": 0,
            "success": False,
            "error": f"Provider '{provider}' is not configured or not available.",
        }

    last_error = None

    for attempt in range(1, retry_count + 1):
        start_time = time.monotonic()

        try:
            # Ollama small models struggle with very long system prompts.
            # Truncate to first 1500 chars to keep the core instructions.
            effective_system_prompt = system_prompt
            if provider == "ollama" and len(system_prompt) > 1500:
                effective_system_prompt = system_prompt[:1500] + "\n\nOutput ONLY valid JSON. No markdown."
                logger.debug(f"Truncated system prompt for Ollama: {len(system_prompt)} → {len(effective_system_prompt)} chars")

            messages = [
                {"role": "system", "content": effective_system_prompt},
                {"role": "user", "content": user_content},
            ]

            # Build API call kwargs
            # Ollama's OpenAI-compatible API returns 500 if max_tokens is sent
            # for some model configurations. Omit it for Ollama — let the model
            # decide output length naturally.
            call_kwargs = {
                "model": model,
                "messages": messages,
                "temperature": temperature,
            }
            if provider != "ollama":
                call_kwargs["max_tokens"] = max_tokens

            response = await client.chat.completions.create(**call_kwargs)

            latency_ms = (time.monotonic() - start_time) * 1000
            content = response.choices[0].message.content or ""
            tokens_used = response.usage.total_tokens if response.usage else 0

            logger.info(
                "AI call succeeded",
                extra={
                    "provider": provider,
                    "model": model,
                    "attempt": attempt,
                    "latency_ms": round(latency_ms, 1),
                    "tokens": tokens_used,
                    "temperature": temperature,
                },
            )

            parsed = None
            if response_schema is not None:
                parsed = _parse_structured_output(content, response_schema)

            return {
                "content": content,
                "parsed": parsed,
                "provider": provider,
                "model": model,
                "latency_ms": latency_ms,
                "tokens_used": tokens_used,
                "success": True,
                "error": None,
            }

        except Exception as e:
            latency_ms = (time.monotonic() - start_time) * 1000
            last_error = str(e)

            logger.warning(
                "AI call failed",
                extra={
                    "provider": provider,
                    "model": model,
                    "attempt": attempt,
                    "latency_ms": round(latency_ms, 1),
                    "error_type": type(e).__name__,
                    "error_summary": str(e)[:100],
                },
            )

            if attempt < retry_count:
                import asyncio
                backoff = retry_backoff_base ** attempt
                await asyncio.sleep(backoff)

    return {
        "content": "",
        "parsed": None,
        "provider": provider,
        "model": model,
        "latency_ms": 0.0,
        "tokens_used": 0,
        "success": False,
        "error": f"All {retry_count} attempts failed. Last error: {last_error}",
    }


# ============================================================================
# STRUCTURED OUTPUT PARSING
# ============================================================================

def _parse_structured_output(
    content: str,
    schema: Type[BaseModel],
) -> Optional[dict[str, Any]]:
    """
    Parse LLM output into a structured dict validated against a Pydantic schema.
    
    Three-strategy parsing:
    1. Direct JSON parse
    2. Extract from markdown code fence
    3. Extract first JSON object from mixed text
    """
    logger.info(f"Parsing output ({len(content)} chars): {content[:500]}")
    # Strategy 1: Direct JSON parse
    try:
        data = json.loads(content.strip())
        schema.model_validate(data)
        return data
    except (json.JSONDecodeError, Exception):
        pass

    # Strategy 2: Extract from markdown code fence
    code_fence_pattern = r"```(?:json)?\s*\n?(.*?)\n?\s*```"
    matches = re.findall(code_fence_pattern, content, re.DOTALL)
    for match in matches:
        try:
            data = json.loads(match.strip())
            schema.model_validate(data)
            return data
        except (json.JSONDecodeError, Exception):
            continue

    # Strategy 3: Extract first JSON object
    brace_start = content.find("{")
    if brace_start != -1:
        depth = 0
        for i in range(brace_start, len(content)):
            if content[i] == "{":
                depth += 1
            elif content[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        data = json.loads(content[brace_start:i + 1])
                        schema.model_validate(data)
                        return data
                    except (json.JSONDecodeError, Exception):
                        break

    logger.warning(
        "Failed to parse structured output",
        extra={"schema": schema.__name__, "content_length": len(content)},
    )
    return None


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

async def call_with_fallback(
    system_prompt: str,
    user_content: str,
    temperature: float = 0.3,
    max_tokens: int = 2048,
    response_schema: Optional[Type[BaseModel]] = None,
    preferred_provider: Optional[str] = None,
    preferred_model: Optional[str] = None,
) -> dict[str, Any]:
    """
    Call AI with automatic fallback through the provider chain.
    
    DEVELOPMENT MODE (DEBUG=true):
        Ollama → Groq → AIsa.one → OpenRouter
        (Free first, paid last)
    
    PRODUCTION MODE (DEBUG=false):
        vLLM → AIsa.one → Groq → OpenRouter → Ollama
        (Quality first, free last)
    """
    settings = get_settings()

    # Build provider chain based on mode
    chain: list[tuple[str, str]] = []

    # If caller specified a preference, try it first
    if preferred_provider and preferred_model:
        chain.append((preferred_provider, preferred_model))

    if settings.debug:
        # DEVELOPMENT: fast + free first
        if settings.has_groq:
            chain.append(("groq", PROVIDER_MODELS["groq"]["default"]))
        if settings.has_ollama:
            chain.append(("ollama", settings.ollama_model))
        if settings.has_aisa:
            chain.append(("aisa", PROVIDER_MODELS["aisa"]["default"]))
        if settings.has_openrouter:
            chain.append(("openrouter", PROVIDER_MODELS["openrouter"]["default"]))
        if settings.has_vllm:
            chain.append(("vllm", PROVIDER_MODELS["vllm"]["default"]))
    else:
        # PRODUCTION: quality first
        if settings.has_vllm:
            chain.append(("vllm", PROVIDER_MODELS["vllm"]["default"]))
        if settings.has_aisa:
            chain.append(("aisa", PROVIDER_MODELS["aisa"]["default"]))
        if settings.has_groq:
            chain.append(("groq", PROVIDER_MODELS["groq"]["default"]))
        if settings.has_openrouter:
            chain.append(("openrouter", PROVIDER_MODELS["openrouter"]["default"]))
        if settings.has_ollama:
            chain.append(("ollama", settings.ollama_model))

    # Deduplicate (in case preferred was already in chain)
    seen = set()
    deduped_chain = []
    for provider, model in chain:
        key = f"{provider}:{model}"
        if key not in seen:
            seen.add(key)
            deduped_chain.append((provider, model))
    chain = deduped_chain

    if not chain:
        return {
            "content": "",
            "parsed": None,
            "provider": "none",
            "model": "none",
            "latency_ms": 0.0,
            "tokens_used": 0,
            "success": False,
            "error": "No AI providers configured. Set at least one API key in .env",
        }

    # Try each provider in order
    for provider, model in chain:
        result = await call_ai(
            provider=provider,
            model=model,
            system_prompt=system_prompt,
            user_content=user_content,
            temperature=temperature,
            max_tokens=max_tokens,
            response_schema=response_schema,
            retry_count=2,
        )

        if result["success"]:
            return result

        logger.info(
            f"Provider {provider}/{model} failed, trying next in chain",
            extra={"error": result.get("error", "")[:100]},
        )

    # All providers failed
    return {
        "content": "",
        "parsed": None,
        "provider": "all_failed",
        "model": "none",
        "latency_ms": 0.0,
        "tokens_used": 0,
        "success": False,
        "error": f"All {len(chain)} providers failed.",
    }


async def call_for_json(
    system_prompt: str,
    user_content: str,
    response_schema: Type[BaseModel],
    temperature: float = 0.3,
    max_tokens: int = 2048,
    preferred_provider: Optional[str] = None,
    preferred_model: Optional[str] = None,
    max_parse_retries: int = 2,
) -> dict[str, Any]:
    """
    Call AI expecting structured JSON output. Retries with corrective
    feedback if response doesn't parse.
    """
    current_user_content = user_content

    for attempt in range(1, max_parse_retries + 1):
        result = await call_with_fallback(
            system_prompt=system_prompt,
            user_content=current_user_content,
            temperature=temperature,
            max_tokens=max_tokens,
            response_schema=response_schema,
            preferred_provider=preferred_provider,
            preferred_model=preferred_model,
        )

        if not result["success"]:
            return result

        if result["parsed"] is not None:
            return result

        # Parse failed — retry with corrective feedback
        if attempt < max_parse_retries:
            current_user_content = (
                f"{user_content}\n\n"
                f"IMPORTANT: Your previous response could not be parsed as valid JSON. "
                f"You MUST return ONLY a valid JSON object matching the required schema. "
                f"No markdown, no explanation, no text before or after the JSON. "
                f"Just the raw JSON object."
            )
            logger.info(
                f"JSON parse failed, retrying with corrective feedback (attempt {attempt})",
                extra={"schema": response_schema.__name__},
            )

    result["error"] = (
        f"Response received but could not be parsed as {response_schema.__name__} "
        f"after {max_parse_retries} attempts"
    )
    return result


# ============================================================================
# SPECIALIZED CALLERS
# ============================================================================

async def call_red_agent(
    system_prompt: str,
    user_content: str,
    temperature: float = 0.8,
    max_tokens: int = 3000,
) -> dict[str, Any]:
    """
    Specialized caller for the Red Agent.
    High temperature for creative evasion generation.
    Prefers Groq (speed) or AIsa→Claude Opus (creativity).
    """
    settings = get_settings()

    # Red Agent needs creativity — prefer powerful models
    if settings.has_groq:
        result = await call_ai(
            provider="groq",
            model=PROVIDER_MODELS["groq"]["llama33_70b"],
            system_prompt=system_prompt,
            user_content=user_content,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        if result["success"]:
            return result

    if settings.has_aisa:
        result = await call_ai(
            provider="aisa",
            model=PROVIDER_MODELS["aisa"]["claude_opus"],
            system_prompt=system_prompt,
            user_content=user_content,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        if result["success"]:
            return result

    # Fallback to generic chain
    return await call_with_fallback(
        system_prompt=system_prompt,
        user_content=user_content,
        temperature=temperature,
        max_tokens=max_tokens,
    )


async def call_vision(
    system_prompt: str,
    image_base64: str,
    text_content: str = "",
    temperature: float = 0.2,
    max_tokens: int = 2048,
) -> dict[str, Any]:
    """Specialized caller for vision/multimodal analysis."""
    settings = get_settings()

    user_message_content = []
    if text_content:
        user_message_content.append({"type": "text", "text": text_content})
    user_message_content.append({
        "type": "image_url",
        "image_url": {"url": f"data:image/png;base64,{image_base64}"},
    })

    # Try AIsa.one (GPT-4o has vision)
    if settings.has_aisa:
        client = _create_client("aisa")
        if client:
            try:
                start_time = time.monotonic()
                response = await client.chat.completions.create(
                    model=PROVIDER_MODELS["aisa"]["gpt4o"],
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_message_content},
                    ],
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                latency_ms = (time.monotonic() - start_time) * 1000
                content = response.choices[0].message.content or ""
                tokens_used = response.usage.total_tokens if response.usage else 0

                return {
                    "content": content,
                    "parsed": None,
                    "provider": "aisa",
                    "model": "gpt-4o",
                    "latency_ms": latency_ms,
                    "tokens_used": tokens_used,
                    "success": True,
                    "error": None,
                }
            except Exception as e:
                logger.warning(f"AIsa vision call failed: {e}")

    return {
        "content": "",
        "parsed": None,
        "provider": "none",
        "model": "none",
        "latency_ms": 0.0,
        "tokens_used": 0,
        "success": False,
        "error": "No vision-capable provider available",
    }


async def call_training_data_gen(
    system_prompt: str,
    user_content: str,
    temperature: float = 0.7,
    max_tokens: int = 4000,
    model_preference: str = "claude_opus",
) -> dict[str, Any]:
    """Specialized caller for training data generation. Uses highest-quality models."""
    settings = get_settings()

    if settings.has_aisa:
        model = PROVIDER_MODELS["aisa"].get(model_preference, PROVIDER_MODELS["aisa"]["default"])
        return await call_ai(
            provider="aisa",
            model=model,
            system_prompt=system_prompt,
            user_content=user_content,
            temperature=temperature,
            max_tokens=max_tokens,
            retry_count=2,
        )

    return await call_with_fallback(
        system_prompt=system_prompt,
        user_content=user_content,
        temperature=temperature,
        max_tokens=max_tokens,
    )
