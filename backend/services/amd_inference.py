"""
IMMUNIS ACIN — AMD MI300X Inference Client
vLLM inference on AMD Instinct MI300X GPUs via ROCm.

Connects to a vLLM server hosting IMMUNIS fine-tuned models:
- IMMUNIS-Sentinel (Qwen2.5-7B fine-tuned for threat detection)
- IMMUNIS-Adversary (Llama-3.1-8B fine-tuned for evasion generation)
- IMMUNIS-Vision (Qwen2-VL-7B fine-tuned for visual threat analysis)

The vLLM server runs on AMD MI300X with ROCm, providing:
- PagedAttention for efficient KV cache management
- Continuous batching for high throughput
- Tensor parallelism across MI300X chiplets
- OpenAI-compatible API for seamless integration

Design philosophy:
- Graceful degradation: if vLLM is unavailable, fall back to cloud providers
- Health monitoring: continuous checks prevent routing to dead servers
- Batch optimisation: group requests for throughput
- Cost tracking: monitor GPU utilisation and inference costs
"""

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncGenerator, Optional

logger = logging.getLogger("immunis.services.amd_inference")


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class ModelID(str, Enum):
    """IMMUNIS fine-tuned model identifiers."""
    SENTINEL = "immunis-sentinel"
    ADVERSARY = "immunis-adversary"
    VISION = "immunis-vision"


class ServerStatus(str, Enum):
    """vLLM server health status."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ModelInfo:
    """Information about a loaded model."""
    model_id: str
    model_name: str
    base_model: str
    max_tokens: int
    loaded: bool = False
    gpu_memory_mb: float = 0.0
    quantisation: str = "none"
    adapter_path: str = ""

    def to_dict(self) -> dict:
        return {
            "model_id": self.model_id,
            "model_name": self.model_name,
            "base_model": self.base_model,
            "max_tokens": self.max_tokens,
            "loaded": self.loaded,
            "gpu_memory_mb": self.gpu_memory_mb,
            "quantisation": self.quantisation,
        }


@dataclass
class InferenceRequest:
    """A single inference request."""
    request_id: str
    model_id: ModelID
    prompt: str
    system_prompt: str = ""
    temperature: float = 0.3
    max_tokens: int = 2048
    top_p: float = 0.95
    stop_sequences: list[str] = field(default_factory=list)
    stream: bool = False
    images: list[str] = field(default_factory=list)  # Base64 images for vision model
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "model_id": self.model_id.value,
            "prompt_length": len(self.prompt),
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "stream": self.stream,
            "has_images": len(self.images) > 0,
        }


@dataclass
class InferenceResponse:
    """Response from inference."""
    request_id: str
    model_id: str
    text: str
    tokens_generated: int = 0
    tokens_prompt: int = 0
    latency_ms: float = 0.0
    finish_reason: str = "stop"
    error: Optional[str] = None

    @property
    def tokens_per_second(self) -> float:
        if self.latency_ms <= 0:
            return 0.0
        return (self.tokens_generated / self.latency_ms) * 1000.0

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "model_id": self.model_id,
            "text_length": len(self.text),
            "tokens_generated": self.tokens_generated,
            "tokens_prompt": self.tokens_prompt,
            "latency_ms": round(self.latency_ms, 1),
            "tokens_per_second": round(self.tokens_per_second, 1),
            "finish_reason": self.finish_reason,
            "error": self.error,
        }


@dataclass
class ServerHealth:
    """vLLM server health information."""
    status: ServerStatus
    endpoint: str
    last_check: float
    latency_ms: float = 0.0
    models_loaded: list[str] = field(default_factory=list)
    gpu_utilisation: float = 0.0
    gpu_memory_used_mb: float = 0.0
    gpu_memory_total_mb: float = 0.0
    pending_requests: int = 0
    requests_completed: int = 0
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "status": self.status.value,
            "endpoint": self.endpoint,
            "last_check": self.last_check,
            "latency_ms": round(self.latency_ms, 1),
            "models_loaded": self.models_loaded,
            "gpu_utilisation": round(self.gpu_utilisation, 2),
            "gpu_memory_used_mb": round(self.gpu_memory_used_mb, 1),
            "gpu_memory_total_mb": round(self.gpu_memory_total_mb, 1),
            "pending_requests": self.pending_requests,
            "requests_completed": self.requests_completed,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Model registry
# ---------------------------------------------------------------------------

IMMUNIS_MODELS: dict[ModelID, ModelInfo] = {
    ModelID.SENTINEL: ModelInfo(
        model_id=ModelID.SENTINEL.value,
        model_name="IMMUNIS-Sentinel",
        base_model="Qwen/Qwen2.5-7B",
        max_tokens=8192,
        quantisation="QLoRA-4bit-NF4",
        adapter_path="models/immunis-sentinel-adapter",
    ),
    ModelID.ADVERSARY: ModelInfo(
        model_id=ModelID.ADVERSARY.value,
        model_name="IMMUNIS-Adversary",
        base_model="meta-llama/Llama-3.1-8B",
        max_tokens=8192,
        quantisation="QLoRA-4bit-NF4",
        adapter_path="models/immunis-adversary-adapter",
    ),
    ModelID.VISION: ModelInfo(
        model_id=ModelID.VISION.value,
        model_name="IMMUNIS-Vision",
        base_model="Qwen/Qwen2-VL-7B",
        max_tokens=4096,
        quantisation="QLoRA-4bit-NF4",
        adapter_path="models/immunis-vision-adapter",
    ),
}


# ---------------------------------------------------------------------------
# AMD Inference Client
# ---------------------------------------------------------------------------

class AMDInferenceClient:
    """
    Client for vLLM inference on AMD MI300X GPUs.

    Features:
    - OpenAI-compatible API (vLLM serves this natively)
    - Health monitoring with automatic status tracking
    - Batch inference for throughput optimisation
    - Streaming support for real-time responses
    - Request tracking and performance metrics
    - Graceful fallback when server is unavailable
    """

    def __init__(
        self,
        endpoint: str = "http://localhost:8080",
        api_key: str = "",
        health_check_interval: float = 30.0,
        request_timeout: float = 120.0,
        max_retries: int = 2,
    ):
        self.endpoint = endpoint.rstrip("/")
        self.api_key = api_key
        self.health_check_interval = health_check_interval
        self.request_timeout = request_timeout
        self.max_retries = max_retries

        self._health = ServerHealth(
            status=ServerStatus.UNKNOWN,
            endpoint=self.endpoint,
            last_check=0.0,
        )
        self._request_count = 0
        self._total_tokens = 0
        self._total_latency_ms = 0.0
        self._errors = 0
        self._health_check_task: Optional[asyncio.Task] = None

    @property
    def is_available(self) -> bool:
        """Check if server is available for requests."""
        if not self.endpoint or self.endpoint in ("", "http://localhost:8080"):
            # Check if endpoint was explicitly configured
            try:
                from backend.config import settings
                if not settings.has_vllm:
                    return False
            except ImportError:
                pass

        return self._health.status in (ServerStatus.HEALTHY, ServerStatus.DEGRADED)

    @property
    def metrics(self) -> dict[str, Any]:
        """Return inference metrics."""
        avg_latency = self._total_latency_ms / max(self._request_count, 1)
        return {
            "endpoint": self.endpoint,
            "status": self._health.status.value,
            "total_requests": self._request_count,
            "total_tokens": self._total_tokens,
            "total_errors": self._errors,
            "avg_latency_ms": round(avg_latency, 1),
            "health": self._health.to_dict(),
        }

    async def start(self) -> None:
        """Start the health check background task."""
        if self._health_check_task is None or self._health_check_task.done():
            self._health_check_task = asyncio.create_task(self._health_check_loop())
            logger.info(f"AMD inference client started — endpoint: {self.endpoint}")

    async def stop(self) -> None:
        """Stop the health check background task."""
        if self._health_check_task and not self._health_check_task.done():
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
            logger.info("AMD inference client stopped")

    async def check_health(self) -> ServerHealth:
        """Perform a health check against the vLLM server."""
        start = time.time()

        try:
            response = await self._http_get(f"{self.endpoint}/health")
            latency = (time.time() - start) * 1000

            if response.get("status_code") == 200:
                # Try to get model list
                models_response = await self._http_get(f"{self.endpoint}/v1/models")
                models_loaded = []
                if models_response.get("status_code") == 200:
                    try:
                        body = json.loads(models_response.get("body", "{}"))
                        models_loaded = [
                            m.get("id", "") for m in body.get("data", [])
                        ]
                    except (json.JSONDecodeError, KeyError):
                        pass

                self._health = ServerHealth(
                    status=ServerStatus.HEALTHY,
                    endpoint=self.endpoint,
                    last_check=time.time(),
                    latency_ms=latency,
                    models_loaded=models_loaded,
                    requests_completed=self._request_count,
                )
            else:
                self._health = ServerHealth(
                    status=ServerStatus.UNHEALTHY,
                    endpoint=self.endpoint,
                    last_check=time.time(),
                    latency_ms=latency,
                    error=f"Health check returned {response.get('status_code')}",
                )

        except Exception as e:
            self._health = ServerHealth(
                status=ServerStatus.UNHEALTHY,
                endpoint=self.endpoint,
                last_check=time.time(),
                error=str(e),
            )

        return self._health

    async def generate(self, request: InferenceRequest) -> InferenceResponse:
        """
        Generate text using a fine-tuned model on AMD MI300X.

        Uses OpenAI-compatible chat completions API served by vLLM.
        """
        if not self.is_available:
            return InferenceResponse(
                request_id=request.request_id,
                model_id=request.model_id.value,
                text="",
                error="AMD inference server not available",
            )

        # Build OpenAI-compatible request
        messages = []
        if request.system_prompt:
            messages.append({"role": "system", "content": request.system_prompt})

        # Handle vision model with images
        if request.images and request.model_id == ModelID.VISION:
            content = [{"type": "text", "text": request.prompt}]
            for img_b64 in request.images:
                content.append({
                    "type": "image_url",
                    "image_url": {"url": f"data:image/jpeg;base64,{img_b64}"},
                })
            messages.append({"role": "user", "content": content})
        else:
            messages.append({"role": "user", "content": request.prompt})

        payload = {
            "model": request.model_id.value,
            "messages": messages,
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
            "top_p": request.top_p,
            "stream": False,
        }

        if request.stop_sequences:
            payload["stop"] = request.stop_sequences

        # Send request with retries
        start = time.time()
        last_error = None

        for attempt in range(self.max_retries + 1):
            try:
                response = await self._http_post(
                    f"{self.endpoint}/v1/chat/completions",
                    payload=payload,
                    timeout=self.request_timeout,
                )

                latency = (time.time() - start) * 1000

                if response.get("status_code") == 200:
                    try:
                        body = json.loads(response.get("body", "{}"))
                        choice = body.get("choices", [{}])[0]
                        message = choice.get("message", {})
                        usage = body.get("usage", {})

                        self._request_count += 1
                        tokens_gen = usage.get("completion_tokens", 0)
                        self._total_tokens += tokens_gen
                        self._total_latency_ms += latency

                        return InferenceResponse(
                            request_id=request.request_id,
                            model_id=request.model_id.value,
                            text=message.get("content", ""),
                            tokens_generated=tokens_gen,
                            tokens_prompt=usage.get("prompt_tokens", 0),
                            latency_ms=latency,
                            finish_reason=choice.get("finish_reason", "stop"),
                        )
                    except (json.JSONDecodeError, KeyError, IndexError) as e:
                        last_error = f"Response parse error: {e}"
                else:
                    last_error = f"HTTP {response.get('status_code')}: {response.get('body', '')[:200]}"

            except asyncio.TimeoutError:
                last_error = f"Request timed out after {self.request_timeout}s"
            except Exception as e:
                last_error = str(e)

            # Wait before retry
            if attempt < self.max_retries:
                await asyncio.sleep(1.0 * (attempt + 1))

        self._errors += 1
        return InferenceResponse(
            request_id=request.request_id,
            model_id=request.model_id.value,
            text="",
            latency_ms=(time.time() - start) * 1000,
            error=last_error,
        )

    async def generate_simple(
        self,
        prompt: str,
        model_id: ModelID = ModelID.SENTINEL,
        system_prompt: str = "",
        temperature: float = 0.3,
        max_tokens: int = 2048,
    ) -> str:
        """
        Simplified generation interface — returns text string directly.

        Convenience wrapper around generate() for simple use cases.
        """
        request = InferenceRequest(
            request_id=hashlib.sha256(f"{prompt[:50]}:{time.time()}".encode()).hexdigest()[:12],
            model_id=model_id,
            prompt=prompt,
            system_prompt=system_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        response = await self.generate(request)

        if response.error:
            logger.warning(f"AMD inference error: {response.error}")
            return ""

        return response.text

    async def batch_generate(
        self, requests: list[InferenceRequest]
    ) -> list[InferenceResponse]:
        """
        Batch inference — sends multiple requests concurrently.

        vLLM handles continuous batching server-side, so concurrent
        requests are efficiently batched automatically.
        """
        if not requests:
            return []

        tasks = [self.generate(req) for req in requests]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        results: list[InferenceResponse] = []
        for i, resp in enumerate(responses):
            if isinstance(resp, Exception):
                results.append(InferenceResponse(
                    request_id=requests[i].request_id,
                    model_id=requests[i].model_id.value,
                    text="",
                    error=str(resp),
                ))
            else:
                results.append(resp)

        return results

    async def stream_generate(
        self, request: InferenceRequest
    ) -> AsyncGenerator[str, None]:
        """
        Streaming generation — yields text chunks as they're generated.

        Uses Server-Sent Events (SSE) from vLLM's streaming endpoint.
        """
        if not self.is_available:
            yield ""
            return

        messages = []
        if request.system_prompt:
            messages.append({"role": "system", "content": request.system_prompt})
        messages.append({"role": "user", "content": request.prompt})

        payload = {
            "model": request.model_id.value,
            "messages": messages,
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
            "top_p": request.top_p,
            "stream": True,
        }

        try:
            import aiohttp

            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.endpoint}/v1/chat/completions",
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.request_timeout),
                ) as resp:
                    async for line in resp.content:
                        line_str = line.decode("utf-8").strip()
                        if line_str.startswith("data: "):
                            data = line_str[6:]
                            if data == "[DONE]":
                                break
                            try:
                                chunk = json.loads(data)
                                delta = chunk.get("choices", [{}])[0].get("delta", {})
                                content = delta.get("content", "")
                                if content:
                                    yield content
                            except (json.JSONDecodeError, KeyError, IndexError):
                                continue

        except ImportError:
            # No aiohttp — fall back to non-streaming
            response = await self.generate(request)
            if response.text:
                yield response.text
        except Exception as e:
            logger.warning(f"Streaming error: {e}")
            yield ""

    def get_model_info(self, model_id: ModelID) -> Optional[ModelInfo]:
        """Get information about a specific model."""
        info = IMMUNIS_MODELS.get(model_id)
        if info and model_id.value in self._health.models_loaded:
            info.loaded = True
        return info

    def list_models(self) -> list[dict]:
        """List all available models and their status."""
        models = []
        for model_id, info in IMMUNIS_MODELS.items():
            info.loaded = model_id.value in self._health.models_loaded
            models.append(info.to_dict())
        return models

    # -----------------------------------------------------------------------
    # Internal HTTP helpers
    # -----------------------------------------------------------------------

    async def _http_get(self, url: str, timeout: float = 10.0) -> dict[str, Any]:
        """HTTP GET request."""
        try:
            import aiohttp
            headers = {}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as resp:
                    body = await resp.text()
                    return {"status_code": resp.status, "body": body}

        except ImportError:
            import urllib.request
            try:
                req = urllib.request.Request(url)
                if self.api_key:
                    req.add_header("Authorization", f"Bearer {self.api_key}")
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return {"status_code": resp.status, "body": resp.read().decode()}
            except Exception as e:
                return {"status_code": 0, "body": "", "error": str(e)}

        except Exception as e:
            return {"status_code": 0, "body": "", "error": str(e)}

    async def _http_post(
        self, url: str, payload: dict, timeout: float = 120.0
    ) -> dict[str, Any]:
        """HTTP POST request with JSON payload."""
        try:
            import aiohttp
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as resp:
                    body = await resp.text()
                    return {"status_code": resp.status, "body": body}

        except ImportError:
            import urllib.request
            try:
                data = json.dumps(payload).encode("utf-8")
                req = urllib.request.Request(
                    url,
                    data=data,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                if self.api_key:
                    req.add_header("Authorization", f"Bearer {self.api_key}")
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return {"status_code": resp.status, "body": resp.read().decode()}
            except Exception as e:
                return {"status_code": 0, "body": "", "error": str(e)}

        except Exception as e:
            return {"status_code": 0, "body": "", "error": str(e)}

    async def _health_check_loop(self) -> None:
        """Background health check loop."""
        while True:
            try:
                await self.check_health()
                if self._health.status == ServerStatus.HEALTHY:
                    logger.debug(
                        f"AMD vLLM health: OK ({self._health.latency_ms:.0f}ms, "
                        f"{len(self._health.models_loaded)} models)"
                    )
                else:
                    logger.warning(
                        f"AMD vLLM health: {self._health.status.value} "
                        f"({self._health.error or 'unknown error'})"
                    )
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error(f"Health check error: {e}")

            await asyncio.sleep(self.health_check_interval)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

def _create_client() -> AMDInferenceClient:
    """Create AMD inference client from configuration."""
    try:
        from backend.config import settings
        return AMDInferenceClient(
            endpoint=getattr(settings, "vllm_endpoint", "http://localhost:8080"),
            api_key=getattr(settings, "vllm_api_key", ""),
            request_timeout=getattr(settings, "vllm_timeout", 120.0),
        )
    except ImportError:
        return AMDInferenceClient()


amd_client = _create_client()
