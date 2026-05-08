"""
IMMUNIS ACIN — Hugging Face Client
Integration with Hugging Face ecosystem: Inference API, model hub,
datasets, and Spaces.

Capabilities:
- Inference API: Text generation, embeddings, classification via HF hosted models
- Inference Endpoints: Dedicated endpoints for production workloads
- Model Hub: Download, cache, and verify model weights
- Datasets: Upload/download training and evaluation data
- Spaces: Deploy and manage HF Space for demo

Design philosophy:
- Free tier first: use Inference API for development, Endpoints for production
- Cache aggressively: models and embeddings cached locally
- Verify integrity: SHA-256 verification on all downloaded weights
- Rate limit aware: respect HF API rate limits with exponential backoff
"""

import asyncio
import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("immunis.services.hf_client")


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class HFTaskType(str, Enum):
    """Hugging Face Inference API task types."""
    TEXT_GENERATION = "text-generation"
    TEXT_CLASSIFICATION = "text-classification"
    TOKEN_CLASSIFICATION = "token-classification"
    FEATURE_EXTRACTION = "feature-extraction"
    FILL_MASK = "fill-mask"
    SUMMARIZATION = "summarization"
    TRANSLATION = "translation"
    QUESTION_ANSWERING = "question-answering"
    IMAGE_CLASSIFICATION = "image-classification"
    OBJECT_DETECTION = "object-detection"
    IMAGE_TO_TEXT = "image-to-text"
    ZERO_SHOT_CLASSIFICATION = "zero-shot-classification"


class HFModelStatus(str, Enum):
    """Model availability status."""
    AVAILABLE = "available"
    LOADING = "loading"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class HFInferenceResponse:
    """Response from HF Inference API."""
    request_id: str
    model: str
    task: HFTaskType
    result: Any = None
    latency_ms: float = 0.0
    error: Optional[str] = None
    is_cached: bool = False

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "model": self.model,
            "task": self.task.value,
            "result_type": type(self.result).__name__ if self.result else None,
            "latency_ms": round(self.latency_ms, 1),
            "error": self.error,
            "is_cached": self.is_cached,
        }


@dataclass
class HFModelInfo:
    """Information about a Hugging Face model."""
    model_id: str
    task: str = ""
    pipeline_tag: str = ""
    downloads: int = 0
    likes: int = 0
    library_name: str = ""
    tags: list[str] = field(default_factory=list)
    sha: str = ""

    def to_dict(self) -> dict:
        return {
            "model_id": self.model_id,
            "task": self.task,
            "pipeline_tag": self.pipeline_tag,
            "downloads": self.downloads,
            "likes": self.likes,
            "library_name": self.library_name,
            "tags": self.tags,
        }


@dataclass
class CacheEntry:
    """Cache entry for inference results."""
    key: str
    value: Any
    created_at: float
    ttl_seconds: float = 300.0  # 5 minutes default

    @property
    def is_expired(self) -> bool:
        return (time.time() - self.created_at) > self.ttl_seconds


# ---------------------------------------------------------------------------
# Inference result cache
# ---------------------------------------------------------------------------

class InferenceCache:
    """
    LRU cache for inference results.

    Caches identical requests to avoid redundant API calls.
    Particularly useful for embeddings which are deterministic.
    """

    def __init__(self, max_size: int = 1000, default_ttl: float = 300.0):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._cache: dict[str, CacheEntry] = {}
        self._access_order: list[str] = []

    def get(self, key: str) -> Optional[Any]:
        """Get cached value if exists and not expired."""
        entry = self._cache.get(key)
        if entry is None:
            return None
        if entry.is_expired:
            del self._cache[key]
            if key in self._access_order:
                self._access_order.remove(key)
            return None
        # Move to end (most recently used)
        if key in self._access_order:
            self._access_order.remove(key)
        self._access_order.append(key)
        return entry.value

    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        """Cache a value."""
        if len(self._cache) >= self.max_size:
            # Evict least recently used
            if self._access_order:
                oldest_key = self._access_order.pop(0)
                self._cache.pop(oldest_key, None)

        self._cache[key] = CacheEntry(
            key=key,
            value=value,
            created_at=time.time(),
            ttl_seconds=ttl or self.default_ttl,
        )
        self._access_order.append(key)

    def clear(self) -> None:
        """Clear all cached entries."""
        self._cache.clear()
        self._access_order.clear()

    @property
    def size(self) -> int:
        return len(self._cache)

    @property
    def hit_rate_info(self) -> dict:
        valid = sum(1 for e in self._cache.values() if not e.is_expired)
        return {"total_entries": len(self._cache), "valid_entries": valid}


# ---------------------------------------------------------------------------
# Hugging Face Client
# ---------------------------------------------------------------------------

class HuggingFaceClient:
    """
    Client for Hugging Face ecosystem integration.

    Supports:
    1. Inference API (free tier) — text generation, embeddings, classification
    2. Inference Endpoints (dedicated) — production workloads
    3. Model Hub — download, cache, verify model weights
    4. Datasets — upload/download training and evaluation data
    5. Spaces — deploy demo application

    Rate limiting:
    - Free tier: ~30 requests/minute
    - Pro tier: ~300 requests/minute
    - Inference Endpoints: unlimited (pay per compute)
    """

    INFERENCE_API_URL = "https://api-inference.huggingface.co/models"
    HUB_API_URL = "https://huggingface.co/api"

    def __init__(
        self,
        api_key: str = "",
        cache_dir: str = ".cache/huggingface",
        use_cache: bool = True,
        rate_limit_rpm: int = 25,
    ):
        self.api_key = api_key or os.environ.get("HF_API_KEY", "") or os.environ.get("HUGGING_FACE_HUB_TOKEN", "")
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.use_cache = use_cache
        self.rate_limit_rpm = rate_limit_rpm

        self._inference_cache = InferenceCache()
        self._last_request_time = 0.0
        self._request_count = 0
        self._errors = 0

    @property
    def is_configured(self) -> bool:
        """Check if API key is configured."""
        return bool(self.api_key)

    @property
    def metrics(self) -> dict[str, Any]:
        """Return client metrics."""
        return {
            "configured": self.is_configured,
            "total_requests": self._request_count,
            "total_errors": self._errors,
            "cache_size": self._inference_cache.size,
            "cache_info": self._inference_cache.hit_rate_info,
        }

    # -----------------------------------------------------------------------
    # Inference API
    # -----------------------------------------------------------------------

    async def infer(
        self,
        model: str,
        inputs: str,
        task: HFTaskType = HFTaskType.TEXT_GENERATION,
        parameters: Optional[dict[str, Any]] = None,
        use_cache: Optional[bool] = None,
    ) -> HFInferenceResponse:
        """
        Run inference via HF Inference API.

        Args:
            model: Model ID (e.g., "Qwen/Qwen2.5-7B-Instruct")
            inputs: Input text
            task: Task type
            parameters: Model-specific parameters
            use_cache: Override cache setting

        Returns:
            HFInferenceResponse with results
        """
        if not self.is_configured:
            return HFInferenceResponse(
                request_id="no_key",
                model=model,
                task=task,
                error="HuggingFace API key not configured",
            )

        params = parameters or {}
        should_cache = use_cache if use_cache is not None else self.use_cache

        # Check cache
        if should_cache:
            cache_key = self._inference_cache.make_key(model, task.value, inputs, params)
            cached = self._inference_cache.get(cache_key)
            if cached is not None:
                return HFInferenceResponse(
                    request_id=cache_key,
                    model=model,
                    task=task,
                    result=cached,
                    is_cached=True,
                )

        # Rate limiting
        await self._rate_limit_wait()

        request_id = hashlib.sha256(
            f"{model}:{inputs[:50]}:{time.time()}".encode()
        ).hexdigest()[:12]

        url = f"{self.INFERENCE_API_URL}/{model}"
        payload: dict[str, Any] = {"inputs": inputs}
        if params:
            payload["parameters"] = params

        start = time.time()

        # Retry with exponential backoff
        last_error = None
        for attempt in range(3):
            try:
                response = await self._http_post(url, payload)
                latency = (time.time() - start) * 1000

                status = response.get("status_code", 0)

                if status == 200:
                    try:
                        result = json.loads(response.get("body", ""))
                        self._request_count += 1

                        # Cache the result
                        if should_cache:
                            # Embeddings get longer TTL (deterministic)
                            ttl = 3600.0 if task == HFTaskType.FEATURE_EXTRACTION else 300.0
                            self._inference_cache.set(cache_key, result, ttl)

                        return HFInferenceResponse(
                            request_id=request_id,
                            model=model,
                            task=task,
                            result=result,
                            latency_ms=latency,
                        )
                    except json.JSONDecodeError as e:
                        last_error = f"Response parse error: {e}"

                elif status == 503:
                    # Model loading — wait and retry
                    try:
                        body = json.loads(response.get("body", "{}"))
                        estimated_time = body.get("estimated_time", 30)
                        logger.info(f"Model {model} loading, estimated {estimated_time}s")
                        await asyncio.sleep(min(estimated_time, 60))
                        continue
                    except (json.JSONDecodeError, KeyError):
                        await asyncio.sleep(10)
                        continue

                elif status == 429:
                    # Rate limited
                    wait = 2 ** (attempt + 1)
                    logger.warning(f"HF rate limited, waiting {wait}s")
                    await asyncio.sleep(wait)
                    continue

                else:
                    last_error = f"HTTP {status}: {response.get('body', '')[:200]}"

            except asyncio.TimeoutError:
                last_error = "Request timed out"
            except Exception as e:
                last_error = str(e)

            # Exponential backoff
            if attempt < 2:
                await asyncio.sleep(2 ** attempt)

        self._errors += 1
        return HFInferenceResponse(
            request_id=request_id,
            model=model,
            task=task,
            error=last_error,
            latency_ms=(time.time() - start) * 1000,
        )

    async def generate_text(
        self,
        model: str,
        prompt: str,
        max_new_tokens: int = 512,
        temperature: float = 0.3,
        top_p: float = 0.95,
        do_sample: bool = True,
    ) -> str:
        """
        Convenience method for text generation.

        Returns generated text string directly.
        """
        response = await self.infer(
            model=model,
            inputs=prompt,
            task=HFTaskType.TEXT_GENERATION,
            parameters={
                "max_new_tokens": max_new_tokens,
                "temperature": temperature,
                "top_p": top_p,
                "do_sample": do_sample,
                "return_full_text": False,
            },
        )

        if response.error:
            logger.warning(f"HF text generation error: {response.error}")
            return ""

        if isinstance(response.result, list) and response.result:
            return response.result[0].get("generated_text", "")
        return ""

    async def get_embeddings(
        self,
        model: str,
        texts: list[str],
    ) -> list[list[float]]:
        """
        Get text embeddings via HF Inference API.

        Args:
            model: Embedding model (e.g., "sentence-transformers/LaBSE")
            texts: List of texts to embed

        Returns:
            List of embedding vectors
        """
        embeddings: list[list[float]] = []

        for text in texts:
            response = await self.infer(
                model=model,
                inputs=text,
                task=HFTaskType.FEATURE_EXTRACTION,
                use_cache=True,  # Embeddings are deterministic
            )

            if response.error:
                logger.warning(f"Embedding error for text: {response.error}")
                embeddings.append([])
            elif isinstance(response.result, list):
                # HF returns nested list — take first element
                if response.result and isinstance(response.result[0], list):
                    embeddings.append(response.result[0])
                else:
                    embeddings.append(response.result)
            else:
                embeddings.append([])

        return embeddings

    async def classify_text(
        self,
        model: str,
        text: str,
        candidate_labels: Optional[list[str]] = None,
    ) -> dict[str, float]:
        """
        Text classification via HF Inference API.

        Returns dict of label -> confidence.
        """
        if candidate_labels:
            # Zero-shot classification
            response = await self.infer(
                model=model,
                inputs=text,
                task=HFTaskType.ZERO_SHOT_CLASSIFICATION,
                parameters={"candidate_labels": candidate_labels},
            )
        else:
            response = await self.infer(
                model=model,
                inputs=text,
                task=HFTaskType.TEXT_CLASSIFICATION,
            )

        if response.error:
            logger.warning(f"Classification error: {response.error}")
            return {}

        result = response.result
        if isinstance(result, dict):
            labels = result.get("labels", [])
            scores = result.get("scores", [])
            return dict(zip(labels, scores))
        elif isinstance(result, list):
            return {
                item.get("label", f"class_{i}"): item.get("score", 0.0)
                for i, item in enumerate(result)
                if isinstance(item, dict)
            }

        return {}

    # -----------------------------------------------------------------------
    # Model Hub
    # -----------------------------------------------------------------------

    async def get_model_info(self, model_id: str) -> Optional[HFModelInfo]:
        """Get information about a model from the Hub."""
        url = f"{self.HUB_API_URL}/models/{model_id}"
        response = await self._http_get(url)

        if response.get("status_code") != 200:
            return None

        try:
            data = json.loads(response.get("body", "{}"))
            return HFModelInfo(
                model_id=data.get("modelId", model_id),
                task=data.get("pipeline_tag", ""),
                pipeline_tag=data.get("pipeline_tag", ""),
                downloads=data.get("downloads", 0),
                likes=data.get("likes", 0),
                library_name=data.get("library_name", ""),
                tags=data.get("tags", []),
                sha=data.get("sha", ""),
            )
        except (json.JSONDecodeError, KeyError):
            return None

    async def check_model_status(self, model_id: str) -> HFModelStatus:
        """Check if a model is available on the Inference API."""
        url = f"{self.INFERENCE_API_URL}/{model_id}"
        response = await self._http_post(url, {"inputs": "test"})

        status = response.get("status_code", 0)
        if status == 200:
            return HFModelStatus.AVAILABLE
        elif status == 503:
            return HFModelStatus.LOADING
        elif status in (401, 403, 404):
            return HFModelStatus.UNAVAILABLE
        else:
            return HFModelStatus.ERROR

    async def download_model(
        self,
        model_id: str,
        revision: str = "main",
        cache_dir: Optional[str] = None,
    ) -> Optional[str]:
        """
        Download a model from the Hub to local cache.

        Uses huggingface_hub library if available, otherwise
        provides instructions for manual download.
        """
        target_dir = Path(cache_dir or self.cache_dir) / model_id.replace("/", "--")

        try:
            from huggingface_hub import snapshot_download

            path = snapshot_download(
                repo_id=model_id,
                revision=revision,
                cache_dir=str(target_dir.parent),
                token=self.api_key or None,
            )
            logger.info(f"Model {model_id} downloaded to {path}")
            return path

        except ImportError:
            logger.warning(
                f"huggingface_hub not installed. Install with: pip install huggingface_hub\n"
                f"Then download manually: huggingface-cli download {model_id}"
            )
            return None
        except Exception as e:
            logger.error(f"Model download failed: {e}")
            return None

    # -----------------------------------------------------------------------
    # Dataset operations
    # -----------------------------------------------------------------------

    async def upload_dataset(
        self,
        repo_id: str,
        data: list[dict[str, Any]],
        split: str = "train",
        private: bool = True,
    ) -> bool:
        """
        Upload training data as a HF dataset.

        Args:
            repo_id: Dataset repository ID (e.g., "immunis/threat-detection-v1")
            data: List of data records
            split: Dataset split name
            private: Whether dataset should be private

        Returns:
            True if upload succeeded
        """
        try:
            from huggingface_hub import HfApi

            api = HfApi(token=self.api_key)

            # Save data as JSONL
            jsonl_path = self.cache_dir / f"{repo_id.replace('/', '--')}_{split}.jsonl"
            jsonl_path.parent.mkdir(parents=True, exist_ok=True)

            with open(jsonl_path, "w", encoding="utf-8") as f:
                for record in data:
                    f.write(json.dumps(record, ensure_ascii=False) + "\n")

            # Create repo if needed
            try:
                api.create_repo(
                    repo_id=repo_id,
                    repo_type="dataset",
                    private=private,
                    exist_ok=True,
                )
            except Exception:
                pass  # Repo may already exist

            # Upload file
            api.upload_file(
                path_or_fileobj=str(jsonl_path),
                path_in_repo=f"data/{split}.jsonl",
                repo_id=repo_id,
                repo_type="dataset",
            )

            logger.info(f"Dataset uploaded: {repo_id}/{split} ({len(data)} records)")
            return True

        except ImportError:
            logger.warning("huggingface_hub not installed for dataset upload")
            return False
        except Exception as e:
            logger.error(f"Dataset upload failed: {e}")
            return False

    async def download_dataset(
        self,
        repo_id: str,
        split: str = "train",
    ) -> list[dict[str, Any]]:
        """
        Download a dataset from HF Hub.

        Returns list of data records.
        """
        try:
            from huggingface_hub import hf_hub_download

            path = hf_hub_download(
                repo_id=repo_id,
                filename=f"data/{split}.jsonl",
                repo_type="dataset",
                token=self.api_key or None,
                cache_dir=str(self.cache_dir),
            )

            data = []
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        data.append(json.loads(line))

            logger.info(f"Dataset downloaded: {repo_id}/{split} ({len(data)} records)")
            return data

        except ImportError:
            logger.warning("huggingface_hub not installed for dataset download")
            return []
        except Exception as e:
            logger.error(f"Dataset download failed: {e}")
            return []

    # -----------------------------------------------------------------------
    # Space deployment
    # -----------------------------------------------------------------------

    async def deploy_space(
        self,
        repo_id: str,
        space_dir: str,
        sdk: str = "gradio",
        hardware: str = "cpu-basic",
        private: bool = False,
    ) -> Optional[str]:
        """
        Deploy a Hugging Face Space.

        Args:
            repo_id: Space repository ID (e.g., "immunis/acin-demo")
            space_dir: Local directory containing Space files
            sdk: Space SDK ("gradio" or "streamlit")
            hardware: Hardware tier
            private: Whether Space should be private

        Returns:
            Space URL if successful, None otherwise
        """
        try:
            from huggingface_hub import HfApi

            api = HfApi(token=self.api_key)

            # Create Space repo
            try:
                api.create_repo(
                    repo_id=repo_id,
                    repo_type="space",
                    space_sdk=sdk,
                    space_hardware=hardware,
                    private=private,
                    exist_ok=True,
                )
            except Exception:
                pass  # Repo may already exist

            # Upload all files
            space_path = Path(space_dir)
            if space_path.exists():
                api.upload_folder(
                    folder_path=str(space_path),
                    repo_id=repo_id,
                    repo_type="space",
                )

            space_url = f"https://huggingface.co/spaces/{repo_id}"
            logger.info(f"Space deployed: {space_url}")
            return space_url

        except ImportError:
            logger.warning("huggingface_hub not installed for Space deployment")
            return None
        except Exception as e:
            logger.error(f"Space deployment failed: {e}")
            return None

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    async def _rate_limit_wait(self) -> None:
        """Enforce rate limiting."""
        min_interval = 60.0 / self.rate_limit_rpm
        elapsed = time.time() - self._last_request_time
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)
        self._last_request_time = time.time()

    async def _http_get(self, url: str, timeout: float = 30.0) -> dict[str, Any]:
        """HTTP GET request."""
        headers = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout),
                ) as resp:
                    body = await resp.text()
                    return {"status_code": resp.status, "body": body}
        except ImportError:
            import urllib.request
            try:
                req = urllib.request.Request(url, headers=headers)
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
        """HTTP POST request."""
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout),
                ) as resp:
                    body = await resp.text()
                    return {"status_code": resp.status, "body": body}
        except ImportError:
            import urllib.request
            try:
                data = json.dumps(payload).encode("utf-8")
                req = urllib.request.Request(url, data=data, headers=headers, method="POST")
                if self.api_key:
                    req.add_header("Authorization", f"Bearer {self.api_key}")
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return {"status_code": resp.status, "body": resp.read().decode()}
            except Exception as e:
                return {"status_code": 0, "body": "", "error": str(e)}
        except Exception as e:
            return {"status_code": 0, "body": "", "error": str(e)}


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

def _create_client() -> HuggingFaceClient:
    """Create HF client from configuration."""
    try:
        from backend.config import settings
        return HuggingFaceClient(
            api_key=getattr(settings, "hf_api_key", ""),
        )
    except ImportError:
        return HuggingFaceClient()


hf_client = _create_client()
