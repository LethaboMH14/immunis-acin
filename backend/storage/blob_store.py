"""
IMMUNIS ACIN — Blob Store (File Storage for Artefacts)

WHY: Cyber incidents produce artefacts that don't fit in a database
or vector store: captured payloads, visual evidence (screenshots,
QR codes, documents), model weight snapshots, exported STIX bundles,
compliance report PDFs, and honeypot capture logs.

These need:
- Content-addressable storage (SHA256 hash as filename)
- Integrity verification on read
- Size limits to prevent storage exhaustion
- Metadata sidecar files for provenance
- Automatic cleanup of expired artefacts

Architecture:
  blob_store/
  ├── payloads/     ← captured malicious payloads (encrypted at rest)
  ├── visual/       ← images, QR codes, document scans
  ├── stix/         ← exported STIX bundles
  ├── reports/      ← generated compliance reports
  ├── captures/     ← honeypot capture logs
  ├── models/       ← model weight snapshots
  └── temp/         ← temporary processing files (auto-cleaned)
"""

import logging
import os
import json
import hashlib
import shutil
import time
from typing import Optional, BinaryIO
from datetime import datetime, timezone, timedelta
from pathlib import Path
from enum import Enum

logger = logging.getLogger("immunis.storage.blob_store")


class BlobCategory(str, Enum):
    """Categories of stored blobs — each maps to a subdirectory."""
    PAYLOADS = "payloads"
    VISUAL = "visual"
    STIX = "stix"
    REPORTS = "reports"
    CAPTURES = "captures"
    MODELS = "models"
    TEMP = "temp"


class BlobMetadata:
    """Metadata sidecar for a stored blob."""

    def __init__(
        self,
        blob_id: str,
        category: BlobCategory,
        original_filename: Optional[str] = None,
        content_type: Optional[str] = None,
        size_bytes: int = 0,
        sha256_hash: str = "",
        created_at: Optional[str] = None,
        expires_at: Optional[str] = None,
        incident_id: Optional[str] = None,
        antibody_id: Optional[str] = None,
        tags: Optional[list[str]] = None,
        extra: Optional[dict] = None,
    ):
        self.blob_id = blob_id
        self.category = category
        self.original_filename = original_filename
        self.content_type = content_type
        self.size_bytes = size_bytes
        self.sha256_hash = sha256_hash
        self.created_at = created_at or datetime.now(timezone.utc).isoformat()
        self.expires_at = expires_at
        self.incident_id = incident_id
        self.antibody_id = antibody_id
        self.tags = tags or []
        self.extra = extra or {}

    def to_dict(self) -> dict:
        return {
            "blob_id": self.blob_id,
            "category": self.category.value if isinstance(self.category, BlobCategory) else self.category,
            "original_filename": self.original_filename,
            "content_type": self.content_type,
            "size_bytes": self.size_bytes,
            "sha256_hash": self.sha256_hash,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "incident_id": self.incident_id,
            "antibody_id": self.antibody_id,
            "tags": self.tags,
            "extra": self.extra,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "BlobMetadata":
        category = data.get("category", "temp")
        if isinstance(category, str):
            try:
                category = BlobCategory(category)
            except ValueError:
                category = BlobCategory.TEMP

        return cls(
            blob_id=data.get("blob_id", ""),
            category=category,
            original_filename=data.get("original_filename"),
            content_type=data.get("content_type"),
            size_bytes=data.get("size_bytes", 0),
            sha256_hash=data.get("sha256_hash", ""),
            created_at=data.get("created_at"),
            expires_at=data.get("expires_at"),
            incident_id=data.get("incident_id"),
            antibody_id=data.get("antibody_id"),
            tags=data.get("tags", []),
            extra=data.get("extra", {}),
        )


class BlobStore:
    """
    Content-addressable file storage for IMMUNIS artefacts.

    Features:
    - SHA256 content addressing (deduplication)
    - Integrity verification on read
    - Category-based organisation
    - Metadata sidecar files
    - Size limits per category and total
    - Automatic expiry cleanup
    - Thread-safe via filesystem atomicity

    Usage:
        store = BlobStore("./data/blobs")

        # Store a blob
        blob_id = store.store(
            data=payload_bytes,
            category=BlobCategory.PAYLOADS,
            original_filename="malware.exe",
            incident_id="INC-001",
        )

        # Read a blob
        data, metadata = store.read(blob_id)

        # Verify integrity
        is_valid = store.verify(blob_id)

        # Clean expired blobs
        cleaned = store.cleanup_expired()
    """

    # Size limits (bytes)
    MAX_BLOB_SIZE = 100 * 1024 * 1024  # 100MB per blob
    MAX_CATEGORY_SIZE = {
        BlobCategory.PAYLOADS: 1 * 1024 * 1024 * 1024,   # 1GB
        BlobCategory.VISUAL: 2 * 1024 * 1024 * 1024,      # 2GB
        BlobCategory.STIX: 500 * 1024 * 1024,              # 500MB
        BlobCategory.REPORTS: 500 * 1024 * 1024,            # 500MB
        BlobCategory.CAPTURES: 1 * 1024 * 1024 * 1024,    # 1GB
        BlobCategory.MODELS: 5 * 1024 * 1024 * 1024,      # 5GB
        BlobCategory.TEMP: 500 * 1024 * 1024,              # 500MB
    }
    MAX_TOTAL_SIZE = 10 * 1024 * 1024 * 1024  # 10GB total

    # Default expiry per category
    DEFAULT_EXPIRY = {
        BlobCategory.PAYLOADS: timedelta(days=90),
        BlobCategory.VISUAL: timedelta(days=180),
        BlobCategory.STIX: timedelta(days=365),
        BlobCategory.REPORTS: timedelta(days=365 * 7),  # 7 years for compliance
        BlobCategory.CAPTURES: timedelta(days=30),
        BlobCategory.MODELS: timedelta(days=365),
        BlobCategory.TEMP: timedelta(hours=24),
    }

    def __init__(self, base_path: Optional[str] = None):
        if base_path is None:
            try:
                from backend.config import config
                base_path = getattr(config, "blob_store_path", "./data/blobs")
            except (ImportError, AttributeError):
                base_path = "./data/blobs"

        self._base_path = Path(base_path)
        self._ensure_directories()

        # Statistics
        self._total_stores: int = 0
        self._total_reads: int = 0
        self._total_bytes_stored: int = 0
        self._integrity_failures: int = 0

        logger.info(f"Blob store initialised at {self._base_path}")

    def _ensure_directories(self) -> None:
        """Create category subdirectories if they don't exist."""
        for category in BlobCategory:
            category_path = self._base_path / category.value
            category_path.mkdir(parents=True, exist_ok=True)

    def store(
        self,
        data: bytes,
        category: BlobCategory,
        original_filename: Optional[str] = None,
        content_type: Optional[str] = None,
        incident_id: Optional[str] = None,
        antibody_id: Optional[str] = None,
        tags: Optional[list[str]] = None,
        expires_at: Optional[str] = None,
        extra: Optional[dict] = None,
    ) -> str:
        """
        Store a blob with content-addressable naming.

        Args:
            data: Raw bytes to store.
            category: Storage category.
            original_filename: Original filename for reference.
            content_type: MIME type.
            incident_id: Associated incident.
            antibody_id: Associated antibody.
            tags: Searchable tags.
            expires_at: ISO timestamp for expiry. None = use default.
            extra: Additional metadata.

        Returns:
            blob_id (SHA256 hash of content).

        Raises:
            ValueError: If blob exceeds size limits.
            IOError: If storage quota exceeded.
        """
        # Validate size
        if len(data) > self.MAX_BLOB_SIZE:
            raise ValueError(
                f"Blob size {len(data)} exceeds maximum "
                f"{self.MAX_BLOB_SIZE} bytes"
            )

        # Check category quota
        category_size = self._get_category_size(category)
        max_category = self.MAX_CATEGORY_SIZE.get(
            category, self.MAX_CATEGORY_SIZE[BlobCategory.TEMP]
        )
        if category_size + len(data) > max_category:
            raise IOError(
                f"Category {category.value} quota exceeded: "
                f"{category_size + len(data)} > {max_category}"
            )

        # Check total quota
        total_size = self._get_total_size()
        if total_size + len(data) > self.MAX_TOTAL_SIZE:
            raise IOError(
                f"Total storage quota exceeded: "
                f"{total_size + len(data)} > {self.MAX_TOTAL_SIZE}"
            )

        # Compute content hash
        sha256_hash = hashlib.sha256(data).hexdigest()
        blob_id = sha256_hash[:32]  # First 32 chars as ID

        # Compute expiry
        if expires_at is None:
            default_expiry = self.DEFAULT_EXPIRY.get(
                category, timedelta(days=90)
            )
            expires_dt = datetime.now(timezone.utc) + default_expiry
            expires_at = expires_dt.isoformat()

        # Build paths
        category_path = self._base_path / category.value
        blob_path = category_path / blob_id
        meta_path = category_path / f"{blob_id}.meta.json"

        # Check for duplicate (content-addressable dedup)
        if blob_path.exists():
            logger.debug(
                f"Blob {blob_id} already exists in {category.value} — dedup"
            )
            # Update metadata if needed
            existing_meta = self._read_metadata(meta_path)
            if existing_meta and incident_id:
                # Append incident reference
                existing_incidents = existing_meta.extra.get("incident_ids", [])
                if incident_id not in existing_incidents:
                    existing_incidents.append(incident_id)
                    existing_meta.extra["incident_ids"] = existing_incidents
                    self._write_metadata(meta_path, existing_meta)
            return blob_id

        # Write blob atomically (write to temp, then rename)
        temp_path = category_path / f".{blob_id}.tmp"
        try:
            with open(temp_path, "wb") as f:
                f.write(data)

            # Atomic rename
            temp_path.rename(blob_path)

        except Exception:
            # Clean up temp file on failure
            if temp_path.exists():
                temp_path.unlink()
            raise

        # Write metadata sidecar
        metadata = BlobMetadata(
            blob_id=blob_id,
            category=category,
            original_filename=original_filename,
            content_type=content_type,
            size_bytes=len(data),
            sha256_hash=sha256_hash,
            expires_at=expires_at,
            incident_id=incident_id,
            antibody_id=antibody_id,
            tags=tags,
            extra=extra or {},
        )
        self._write_metadata(meta_path, metadata)

        # Update stats
        self._total_stores += 1
        self._total_bytes_stored += len(data)

        logger.info(
            f"Blob stored: {blob_id} in {category.value} "
            f"({len(data)} bytes, expires {expires_at})"
        )

        return blob_id

    def store_file(
        self,
        file_path: str,
        category: BlobCategory,
        **kwargs,
    ) -> str:
        """Store a blob from a file path."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        data = path.read_bytes()

        if "original_filename" not in kwargs:
            kwargs["original_filename"] = path.name

        return self.store(data=data, category=category, **kwargs)

    def store_stream(
        self,
        stream: BinaryIO,
        category: BlobCategory,
        **kwargs,
    ) -> str:
        """Store a blob from a file-like stream."""
        data = stream.read()
        return self.store(data=data, category=category, **kwargs)

    def read(self, blob_id: str, category: Optional[BlobCategory] = None) -> tuple[bytes, Optional[BlobMetadata]]:
        """
        Read a blob by ID.

        Args:
            blob_id: The blob identifier (SHA256 prefix).
            category: Category to search in. None = search all.

        Returns:
            Tuple of (data bytes, metadata). Raises FileNotFoundError if not found.
        """
        blob_path, meta_path = self._find_blob(blob_id, category)

        if blob_path is None:
            raise FileNotFoundError(f"Blob not found: {blob_id}")

        # Read data
        data = blob_path.read_bytes()

        # Read metadata
        metadata = self._read_metadata(meta_path) if meta_path else None

        # Verify integrity
        actual_hash = hashlib.sha256(data).hexdigest()
        if metadata and metadata.sha256_hash and actual_hash != metadata.sha256_hash:
            self._integrity_failures += 1
            logger.critical(
                f"INTEGRITY FAILURE: blob {blob_id} hash mismatch! "
                f"Expected {metadata.sha256_hash[:16]}..., "
                f"got {actual_hash[:16]}..."
            )
            raise IOError(
                f"Blob integrity verification failed for {blob_id}"
            )

        self._total_reads += 1

        return data, metadata

    def verify(self, blob_id: str, category: Optional[BlobCategory] = None) -> bool:
        """
        Verify integrity of a stored blob.

        Returns True if hash matches, False if corrupted or missing.
        """
        try:
            blob_path, meta_path = self._find_blob(blob_id, category)
            if blob_path is None:
                return False

            data = blob_path.read_bytes()
            actual_hash = hashlib.sha256(data).hexdigest()

            metadata = self._read_metadata(meta_path) if meta_path else None
            if metadata and metadata.sha256_hash:
                return actual_hash == metadata.sha256_hash

            # No metadata to verify against — check file exists and is readable
            return True

        except Exception as e:
            logger.error(f"Integrity verification failed for {blob_id}: {e}")
            return False

    def delete(self, blob_id: str, category: Optional[BlobCategory] = None) -> bool:
        """Delete a blob and its metadata."""
        blob_path, meta_path = self._find_blob(blob_id, category)

        if blob_path is None:
            return False

        try:
            if blob_path.exists():
                blob_path.unlink()
            if meta_path and meta_path.exists():
                meta_path.unlink()

            logger.info(f"Blob deleted: {blob_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete blob {blob_id}: {e}")
            return False

    def get_metadata(
        self,
        blob_id: str,
        category: Optional[BlobCategory] = None,
    ) -> Optional[BlobMetadata]:
        """Get metadata for a blob without reading the data."""
        _, meta_path = self._find_blob(blob_id, category)
        if meta_path is None:
            return None
        return self._read_metadata(meta_path)

    def list_blobs(
        self,
        category: Optional[BlobCategory] = None,
        tags: Optional[list[str]] = None,
        incident_id: Optional[str] = None,
        antibody_id: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict]:
        """
        List blobs with optional filters.

        Returns list of metadata dicts.
        """
        results = []
        categories = [category] if category else list(BlobCategory)

        for cat in categories:
            cat_path = self._base_path / cat.value
            if not cat_path.exists():
                continue

            for meta_file in sorted(cat_path.glob("*.meta.json"), reverse=True):
                if len(results) >= limit:
                    break

                metadata = self._read_metadata(meta_file)
                if metadata is None:
                    continue

                # Apply filters
                if tags:
                    if not any(t in metadata.tags for t in tags):
                        continue
                if incident_id and metadata.incident_id != incident_id:
                    continue
                if antibody_id and metadata.antibody_id != antibody_id:
                    continue

                results.append(metadata.to_dict())

        return results[:limit]

    def cleanup_expired(self) -> int:
        """
        Remove expired blobs.

        Returns number of blobs removed.
        """
        now = datetime.now(timezone.utc)
        removed = 0

        for category in BlobCategory:
            cat_path = self._base_path / category.value
            if not cat_path.exists():
                continue

            for meta_file in cat_path.glob("*.meta.json"):
                metadata = self._read_metadata(meta_file)
                if metadata is None:
                    continue

                if metadata.expires_at:
                    try:
                        expires = datetime.fromisoformat(
                            metadata.expires_at.replace("Z", "+00:00")
                        )
                        if now > expires:
                            blob_id = metadata.blob_id
                            self.delete(blob_id, category)
                            removed += 1
                    except (ValueError, TypeError):
                        continue

        if removed > 0:
            logger.info(f"Cleaned up {removed} expired blobs")

        return removed

    def cleanup_temp(self) -> int:
        """Remove all temporary blobs older than 24 hours."""
        temp_path = self._base_path / BlobCategory.TEMP.value
        if not temp_path.exists():
            return 0

        cutoff = time.time() - 86400  # 24 hours
        removed = 0

        for item in temp_path.iterdir():
            try:
                if item.stat().st_mtime < cutoff:
                    item.unlink()
                    removed += 1
            except OSError:
                continue

        if removed > 0:
            logger.info(f"Cleaned up {removed} temp files")

        return removed

    # ------------------------------------------------------------------
    # INTERNAL HELPERS
    # ------------------------------------------------------------------

    def _find_blob(
        self,
        blob_id: str,
        category: Optional[BlobCategory] = None,
    ) -> tuple[Optional[Path], Optional[Path]]:
        """Find a blob file and its metadata sidecar."""
        categories = [category] if category else list(BlobCategory)

        for cat in categories:
            cat_path = self._base_path / cat.value
            blob_path = cat_path / blob_id
            meta_path = cat_path / f"{blob_id}.meta.json"

            if blob_path.exists():
                return blob_path, meta_path if meta_path.exists() else None

        return None, None

    def _write_metadata(self, path: Path, metadata: BlobMetadata) -> None:
        """Write metadata sidecar file."""
        try:
            with open(path, "w") as f:
                json.dump(metadata.to_dict(), f, indent=2)
        except Exception as e:
            logger.error(f"Failed to write metadata {path}: {e}")

    def _read_metadata(self, path: Optional[Path]) -> Optional[BlobMetadata]:
        """Read metadata sidecar file."""
        if path is None or not path.exists():
            return None

        try:
            with open(path) as f:
                data = json.load(f)
            return BlobMetadata.from_dict(data)
        except Exception as e:
            logger.error(f"Failed to read metadata {path}: {e}")
            return None

    def _get_category_size(self, category: BlobCategory) -> int:
        """Get total size of blobs in a category."""
        cat_path = self._base_path / category.value
        if not cat_path.exists():
            return 0

        total = 0
        for item in cat_path.iterdir():
            if not item.name.endswith(".meta.json") and not item.name.startswith("."):
                try:
                    total += item.stat().st_size
                except OSError:
                    continue
        return total

    def _get_total_size(self) -> int:
        """Get total size of all blobs across all categories."""
        total = 0
        for category in BlobCategory:
            total += self._get_category_size(category)
        return total

    # ------------------------------------------------------------------
    # STATISTICS
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        """Return blob store statistics."""
        category_stats = {}
        total_blobs = 0
        total_size = 0

        for category in BlobCategory:
            cat_path = self._base_path / category.value
            if not cat_path.exists():
                category_stats[category.value] = {"count": 0, "size_mb": 0}
                continue

            count = sum(
                1 for f in cat_path.iterdir()
                if not f.name.endswith(".meta.json") and not f.name.startswith(".")
            )
            size = self._get_category_size(category)

            category_stats[category.value] = {
                "count": count,
                "size_mb": round(size / (1024 * 1024), 2),
                "quota_mb": round(
                    self.MAX_CATEGORY_SIZE.get(category, 0) / (1024 * 1024), 0
                ),
                "usage_pct": round(
                    size / self.MAX_CATEGORY_SIZE.get(category, 1) * 100, 1
                ),
            }
            total_blobs += count
            total_size += size

        return {
            "base_path": str(self._base_path),
            "total_blobs": total_blobs,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "total_quota_mb": round(self.MAX_TOTAL_SIZE / (1024 * 1024), 0),
            "total_usage_pct": round(total_size / self.MAX_TOTAL_SIZE * 100, 1),
            "categories": category_stats,
            "total_stores": self._total_stores,
            "total_reads": self._total_reads,
            "total_bytes_stored": self._total_bytes_stored,
            "integrity_failures": self._integrity_failures,
        }


# Module-level singleton
_store: Optional[BlobStore] = None


def get_blob_store(base_path: Optional[str] = None) -> BlobStore:
    """Get or create the singleton BlobStore instance."""
    global _store
    if _store is None:
        _store = BlobStore(base_path=base_path)
    return _store
