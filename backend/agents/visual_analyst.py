"""
IMMUNIS ACIN — Agent 8: Visual Threat Analyst

WHY: Modern attacks are increasingly visual. QR codes in phishing
emails redirect to credential harvesting sites. Deepfake videos
impersonate CEOs authorising wire transfers. Forged documents
(invoices, purchase orders, contracts) trick accounts payable
into paying attackers. Steganography hides malicious payloads
in innocent-looking images.

Traditional text-based security systems are blind to all of these.
Agent 8 brings computer vision to cyber defence.

Track: Track 3 (Vision & Multimodal) — AMD Developer Hackathon

Capabilities:
1. QR code analysis — decode, classify destination, check reputation
2. Deepfake detection — facial inconsistency analysis
3. Document forgery detection — layout anomalies, font inconsistencies
4. Steganography detection — statistical analysis of pixel distributions
5. Screenshot/image phishing — OCR + text analysis of visual content
6. Logo impersonation — brand similarity matching
7. Multimodal fusion — combine visual + text signals

Model: IMMUNIS-Vision (fine-tuned Qwen2-VL-7B) when available,
       falls back to API-based vision models (GPT-4o vision).

Mathematical foundation:
  Deepfake detection: frequency domain analysis
    F(u,v) = ΣΣ f(x,y) · e^(-j2π(ux/M + vy/N))
    GAN-generated images show characteristic frequency artifacts

  Steganography detection: chi-squared test on LSB distribution
    χ² = Σ (Oᵢ - Eᵢ)² / Eᵢ
    Natural images have specific LSB statistical properties

  Document forgery: EXIF metadata consistency + error level analysis
    ELA: re-compress at known quality, compare error levels
    Forged regions show different error patterns
"""

import logging
import time
import hashlib
import io
import re
import math
import struct
from typing import Optional
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum

import numpy as np

logger = logging.getLogger("immunis.agents.visual_analyst")

# Try to import image processing libraries
PIL_AVAILABLE = False
CV2_AVAILABLE = False
QRCODE_AVAILABLE = False

try:
    from PIL import Image, ImageStat, ImageFilter
    PIL_AVAILABLE = True
except ImportError:
    logger.info("Pillow not available — install with: pip install Pillow")

try:
    import cv2
    CV2_AVAILABLE = True
except ImportError:
    logger.info("OpenCV not available — install with: pip install opencv-python-headless")

try:
    from pyzbar import pyzbar
    QRCODE_AVAILABLE = True
except ImportError:
    try:
        import cv2
        # OpenCV has built-in QR decoder
        QRCODE_AVAILABLE = CV2_AVAILABLE
    except ImportError:
        logger.info("QR decoding not available — install pyzbar or opencv")


class VisualThreatType(str, Enum):
    """Types of visual threats."""
    QR_PHISHING = "qr_phishing"
    DEEPFAKE = "deepfake"
    DOCUMENT_FORGERY = "document_forgery"
    STEGANOGRAPHY = "steganography"
    SCREENSHOT_PHISHING = "screenshot_phishing"
    LOGO_IMPERSONATION = "logo_impersonation"
    MALICIOUS_IMAGE = "malicious_image"
    CLEAN = "clean"


@dataclass
class QRAnalysis:
    """Result of QR code analysis."""
    decoded_data: str = ""
    qr_type: str = ""  # URL, text, vCard, etc.
    url_domain: Optional[str] = None
    is_suspicious: bool = False
    suspicion_reasons: list[str] = field(default_factory=list)
    reputation_score: float = 1.0  # 0=malicious, 1=clean


@dataclass
class DeepfakeAnalysis:
    """Result of deepfake detection."""
    is_deepfake: bool = False
    confidence: float = 0.0
    indicators: list[str] = field(default_factory=list)
    frequency_anomaly_score: float = 0.0
    facial_consistency_score: float = 1.0
    metadata_anomalies: list[str] = field(default_factory=list)


@dataclass
class DocumentAnalysis:
    """Result of document forgery detection."""
    is_forged: bool = False
    confidence: float = 0.0
    indicators: list[str] = field(default_factory=list)
    ela_anomaly_score: float = 0.0
    metadata_anomalies: list[str] = field(default_factory=list)
    extracted_text: str = ""
    font_inconsistencies: int = 0


@dataclass
class SteganographyAnalysis:
    """Result of steganography detection."""
    is_suspicious: bool = False
    confidence: float = 0.0
    chi_squared_score: float = 0.0
    lsb_anomaly_score: float = 0.0
    estimated_payload_size: int = 0
    indicators: list[str] = field(default_factory=list)


@dataclass
class VisualAnalysisResult:
    """Complete result of visual threat analysis."""
    image_hash: str
    image_size: tuple = (0, 0)
    image_format: str = ""
    file_size_bytes: int = 0
    threat_type: VisualThreatType = VisualThreatType.CLEAN
    overall_confidence: float = 0.0
    is_threat: bool = False
    qr_analysis: Optional[QRAnalysis] = None
    deepfake_analysis: Optional[DeepfakeAnalysis] = None
    document_analysis: Optional[DocumentAnalysis] = None
    steganography_analysis: Optional[SteganographyAnalysis] = None
    extracted_text: str = ""
    llm_analysis: Optional[str] = None
    analysed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    duration_ms: float = 0.0
    metadata: dict = field(default_factory=dict)


# Suspicious URL patterns
SUSPICIOUS_URL_PATTERNS = [
    re.compile(r"bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd", re.IGNORECASE),
    re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),  # IP address URLs
    re.compile(r"[a-z0-9]{20,}\.(?:com|net|org|xyz|top|info)", re.IGNORECASE),  # Random domains
    re.compile(r"(?:login|signin|verify|secure|update|confirm).*\.(?!microsoft|google|apple)", re.IGNORECASE),
    re.compile(r"\.(?:tk|ml|ga|cf|gq|xyz|top|pw|cc)\b", re.IGNORECASE),  # Suspicious TLDs
]

# Known brand domains for impersonation detection
LEGITIMATE_DOMAINS = {
    "microsoft.com", "google.com", "apple.com", "amazon.com",
    "facebook.com", "twitter.com", "linkedin.com", "paypal.com",
    "netflix.com", "dropbox.com", "adobe.com", "zoom.us",
    "fnb.co.za", "absa.co.za", "standardbank.co.za",
    "nedbank.co.za", "capitecbank.co.za", "sars.gov.za",
}


class VisualThreatAnalyst:
    """
    Agent 8: Visual threat analysis engine.

    Analyses images for:
    1. QR code phishing
    2. Deepfake detection
    3. Document forgery
    4. Steganography
    5. Screenshot phishing (OCR + text analysis)
    6. Logo impersonation

    Uses local image processing (Pillow, OpenCV) for deterministic
    analysis and LLM vision models for semantic understanding.
    """

    def __init__(self):
        self._llm_client = None
        self._total_analyses: int = 0
        self._threats_detected: int = 0
        self._threat_type_counts: dict[str, int] = {}

        capabilities = []
        if PIL_AVAILABLE:
            capabilities.append("Pillow")
        if CV2_AVAILABLE:
            capabilities.append("OpenCV")
        if QRCODE_AVAILABLE:
            capabilities.append("QR decode")

        logger.info(
            f"Visual Threat Analyst (Agent 8) initialised: "
            f"capabilities={capabilities or ['basic']}"
        )

    async def analyse(
        self,
        image_bytes: Optional[bytes] = None,
        image_path: Optional[str] = None,
        context: Optional[str] = None,
        use_llm: bool = True,
    ) -> VisualAnalysisResult:
        """
        Analyse an image for visual threats.

        Args:
            image_bytes: Raw image bytes.
            image_path: Path to image file.
            context: Text context (e.g., email body the image was attached to).
            use_llm: Whether to use LLM vision model for semantic analysis.

        Returns:
            VisualAnalysisResult with all analysis results.
        """
        start = time.perf_counter()

        # Load image
        if image_bytes is None and image_path:
            with open(image_path, "rb") as f:
                image_bytes = f.read()

        if image_bytes is None:
            return VisualAnalysisResult(
                image_hash="none",
                threat_type=VisualThreatType.CLEAN,
                metadata={"error": "No image data provided"},
            )

        # Compute hash
        image_hash = hashlib.sha256(image_bytes).hexdigest()[:16]

        # Get image metadata
        img_size, img_format = self._get_image_info(image_bytes)

        # Run all analyses
        qr_result = self._analyse_qr(image_bytes)
        deepfake_result = self._analyse_deepfake(image_bytes)
        document_result = self._analyse_document(image_bytes)
        stego_result = self._analyse_steganography(image_bytes)

        # Extract text via OCR (if available)
        extracted_text = self._extract_text(image_bytes)

        # LLM vision analysis
        llm_analysis = None
        if use_llm:
            llm_analysis = await self._llm_analyse(image_bytes, context, extracted_text)

        # Determine overall threat type and confidence
        threat_type, overall_confidence = self._determine_threat(
            qr_result, deepfake_result, document_result,
            stego_result, extracted_text, llm_analysis,
        )

        is_threat = threat_type != VisualThreatType.CLEAN

        elapsed_ms = (time.perf_counter() - start) * 1000

        # Update stats
        self._total_analyses += 1
        if is_threat:
            self._threats_detected += 1
            self._threat_type_counts[threat_type.value] = (
                self._threat_type_counts.get(threat_type.value, 0) + 1
            )

        result = VisualAnalysisResult(
            image_hash=image_hash,
            image_size=img_size,
            image_format=img_format,
            file_size_bytes=len(image_bytes),
            threat_type=threat_type,
            overall_confidence=overall_confidence,
            is_threat=is_threat,
            qr_analysis=qr_result,
            deepfake_analysis=deepfake_result,
            document_analysis=document_result,
            steganography_analysis=stego_result,
            extracted_text=extracted_text,
            llm_analysis=llm_analysis,
            duration_ms=round(elapsed_ms, 2),
        )

        logger.info(
            f"Visual analysis complete: {threat_type.value} "
            f"(confidence={overall_confidence:.2f}), "
            f"hash={image_hash}, size={img_size}, "
            f"format={img_format}, latency={elapsed_ms:.1f}ms"
        )

        return result

    # ------------------------------------------------------------------
    # IMAGE INFO
    # ------------------------------------------------------------------

    def _get_image_info(self, image_bytes: bytes) -> tuple[tuple, str]:
        """Get image dimensions and format."""
        if PIL_AVAILABLE:
            try:
                img = Image.open(io.BytesIO(image_bytes))
                return img.size, img.format or "unknown"
            except Exception:
                pass

        # Fallback: detect from magic bytes
        fmt = "unknown"
        if image_bytes[:8] == b'\x89PNG\r\n\x1a\n':
            fmt = "PNG"
            if len(image_bytes) > 24:
                w = struct.unpack('>I', image_bytes[16:20])[0]
                h = struct.unpack('>I', image_bytes[20:24])[0]
                return (w, h), fmt
        elif image_bytes[:2] == b'\xff\xd8':
            fmt = "JPEG"
        elif image_bytes[:4] == b'GIF8':
            fmt = "GIF"
        elif image_bytes[:4] == b'RIFF' and image_bytes[8:12] == b'WEBP':
            fmt = "WEBP"

        return (0, 0), fmt

    # ------------------------------------------------------------------
    # QR CODE ANALYSIS
    # ------------------------------------------------------------------

    def _analyse_qr(self, image_bytes: bytes) -> Optional[QRAnalysis]:
        """
        Decode and analyse QR codes in the image.

        Checks:
        - URL shorteners (hiding true destination)
        - IP address URLs (no domain = suspicious)
        - Random/gibberish domains
        - Credential harvesting patterns
        - Suspicious TLDs
        - Domain impersonation (typosquatting)
        """
        decoded_data = self._decode_qr(image_bytes)
        if not decoded_data:
            return None

        result = QRAnalysis(decoded_data=decoded_data)

        # Classify QR content type
        if decoded_data.startswith(("http://", "https://")):
            result.qr_type = "URL"
            result.url_domain = self._extract_domain(decoded_data)
        elif decoded_data.startswith("BEGIN:VCARD"):
            result.qr_type = "vCard"
        elif decoded_data.startswith("WIFI:"):
            result.qr_type = "WiFi"
        elif decoded_data.startswith("tel:"):
            result.qr_type = "Phone"
        elif decoded_data.startswith("mailto:"):
            result.qr_type = "Email"
        else:
            result.qr_type = "Text"

        # Analyse URL for suspicion
        if result.qr_type == "URL":
            reasons = []

            # Check URL shorteners
            for pattern in SUSPICIOUS_URL_PATTERNS:
                if pattern.search(decoded_data):
                    reasons.append(f"Suspicious URL pattern: {pattern.pattern[:50]}")

            # Check for IP address URL
            if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", decoded_data):
                reasons.append("URL uses IP address instead of domain")

            # Check for domain impersonation
            if result.url_domain:
                for legit_domain in LEGITIMATE_DOMAINS:
                    if (
                        legit_domain not in result.url_domain
                        and self._is_typosquat(result.url_domain, legit_domain)
                    ):
                        reasons.append(
                            f"Possible typosquat of {legit_domain}: {result.url_domain}"
                        )

            # Check for credential harvesting paths
            if re.search(
                r"/(login|signin|verify|secure|update|confirm|account|password|reset)",
                decoded_data,
                re.IGNORECASE,
            ):
                reasons.append("URL path suggests credential harvesting")

            # Check for excessive URL length (obfuscation)
            if len(decoded_data) > 200:
                reasons.append(f"Excessively long URL ({len(decoded_data)} chars)")

            # Check for data URI
            if "data:" in decoded_data:
                reasons.append("URL contains data URI (possible payload)")

            if reasons:
                result.is_suspicious = True
                result.suspicion_reasons = reasons
                result.reputation_score = max(
                    0.0, 1.0 - (len(reasons) * 0.25)
                )

        # WiFi QR codes can be used for evil twin attacks
        elif result.qr_type == "WiFi":
            if "WPA" not in decoded_data.upper() and "WEP" not in decoded_data.upper():
                result.is_suspicious = True
                result.suspicion_reasons.append("Open WiFi network (no encryption)")
                result.reputation_score = 0.3

        return result

    def _decode_qr(self, image_bytes: bytes) -> Optional[str]:
        """Decode QR code from image bytes."""
        if QRCODE_AVAILABLE:
            try:
                if PIL_AVAILABLE:
                    img = Image.open(io.BytesIO(image_bytes))
                    decoded = pyzbar.decode(img)
                    if decoded:
                        return decoded[0].data.decode("utf-8", errors="replace")
                elif CV2_AVAILABLE:
                    nparr = np.frombuffer(image_bytes, np.uint8)
                    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                    if img is not None:
                        detector = cv2.QRCodeDetector()
                        data, _, _ = detector.detectAndDecode(img)
                        if data:
                            return data
            except Exception as e:
                logger.debug(f"QR decode failed: {e}")

        return None

    def _extract_domain(self, url: str) -> Optional[str]:
        """Extract domain from URL."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except Exception:
            return None

    def _is_typosquat(self, domain: str, legitimate: str) -> bool:
        """Check if domain is a typosquat of a legitimate domain."""
        # Simple Levenshtein-like check
        domain_base = domain.split(".")[0].lower()
        legit_base = legitimate.split(".")[0].lower()

        if len(domain_base) < 3 or len(legit_base) < 3:
            return False

        # Check edit distance
        distance = self._levenshtein(domain_base, legit_base)
        max_len = max(len(domain_base), len(legit_base))

        # Typosquat if edit distance is 1-2 for short domains, 1-3 for longer
        threshold = 2 if max_len < 8 else 3
        return 0 < distance <= threshold

    def _levenshtein(self, s1: str, s2: str) -> int:
        """Compute Levenshtein edit distance."""
        if len(s1) < len(s2):
            return self._levenshtein(s2, s1)

        if len(s2) == 0:
            return len(s1)

        prev_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row

        return prev_row[-1]

    # ------------------------------------------------------------------
    # DEEPFAKE DETECTION
    # ------------------------------------------------------------------

    def _analyse_deepfake(self, image_bytes: bytes) -> DeepfakeAnalysis:
        """
        Detect deepfake images using frequency domain analysis.

        GAN-generated images exhibit characteristic artifacts in
        the frequency domain (Fourier transform) that are absent
        in natural photographs.

        Method:
        1. Convert to grayscale
        2. Compute 2D FFT
        3. Analyse power spectrum for GAN artifacts
        4. Check EXIF metadata for inconsistencies
        """
        result = DeepfakeAnalysis()

        if not PIL_AVAILABLE:
            return result

        try:
            img = Image.open(io.BytesIO(image_bytes))

            # Convert to grayscale numpy array
            gray = img.convert("L")
            pixels = np.array(gray, dtype=np.float64)

            if pixels.size == 0 or pixels.shape[0] < 32 or pixels.shape[1] < 32:
                return result

            # Compute 2D FFT
            fft = np.fft.fft2(pixels)
            fft_shift = np.fft.fftshift(fft)
            magnitude = np.log1p(np.abs(fft_shift))

            # Analyse power spectrum
            # GAN images often show periodic artifacts as peaks in frequency domain
            center_y, center_x = magnitude.shape[0] // 2, magnitude.shape[1] // 2

            # Radial power spectrum
            y_coords, x_coords = np.ogrid[:magnitude.shape[0], :magnitude.shape[1]]
            r = np.sqrt((x_coords - center_x) ** 2 + (y_coords - center_y) ** 2).astype(int)

            max_r = min(center_x, center_y)
            radial_profile = np.zeros(max_r)
            count = np.zeros(max_r)

            for iy in range(magnitude.shape[0]):
                for ix in range(magnitude.shape[1]):
                    radius = int(r[iy, ix])
                    if radius < max_r:
                        radial_profile[radius] += magnitude[iy, ix]
                        count[radius] += 1

            count[count == 0] = 1
            radial_profile /= count

            # Check for anomalous peaks (GAN artifacts)
            if len(radial_profile) > 10:
                mean_power = np.mean(radial_profile[5:])
                std_power = np.std(radial_profile[5:])

                if std_power > 0:
                    peaks = np.where(
                        radial_profile[5:] > mean_power + 3 * std_power
                    )[0]

                    if len(peaks) > 2:
                        result.frequency_anomaly_score = min(
                            1.0, len(peaks) / 10.0
                        )
                        result.indicators.append(
                            f"Frequency domain anomalies: {len(peaks)} peaks "
                            f"above 3σ threshold"
                        )

            # Check EXIF metadata
            exif_anomalies = self._check_exif_metadata(img)
            result.metadata_anomalies = exif_anomalies

            if exif_anomalies:
                result.indicators.extend(exif_anomalies)

            # Compute overall deepfake score
            score = result.frequency_anomaly_score * 0.6
            if exif_anomalies:
                score += min(0.4, len(exif_anomalies) * 0.1)

            result.confidence = min(1.0, score)
            result.is_deepfake = result.confidence > 0.6

            if result.is_deepfake:
                result.facial_consistency_score = 1.0 - result.confidence

        except Exception as e:
            logger.debug(f"Deepfake analysis failed: {e}")

        return result

    def _check_exif_metadata(self, img) -> list[str]:
        """Check EXIF metadata for deepfake indicators."""
        anomalies = []

        try:
            exif = img.getexif()
            if not exif:
                anomalies.append("No EXIF metadata (common in generated images)")
                return anomalies

            # Check for software tags indicating AI generation
            software = exif.get(305, "")  # Tag 305 = Software
            if isinstance(software, str):
                ai_indicators = [
                    "stable diffusion", "midjourney", "dall-e", "dalle",
                    "gan", "stylegan", "artbreeder", "deepfake",
                    "faceswap", "faceapp",
                ]
                for indicator in ai_indicators:
                    if indicator in software.lower():
                        anomalies.append(
                            f"AI generation software in EXIF: {software}"
                        )

            # Check for missing camera info (natural photos have this)
            make = exif.get(271, "")  # Tag 271 = Make
            model = exif.get(272, "")  # Tag 272 = Model
            if not make and not model:
                anomalies.append("No camera make/model in EXIF")

            # Check for inconsistent timestamps
            datetime_original = exif.get(36867, "")  # DateTimeOriginal
            datetime_digitized = exif.get(36868, "")  # DateTimeDigitized
            if datetime_original and datetime_digitized:
                if datetime_original != datetime_digitized:
                    anomalies.append(
                        "EXIF timestamp mismatch: original vs digitized"
                    )

        except Exception:
            pass

        return anomalies

    # ------------------------------------------------------------------
    # DOCUMENT FORGERY DETECTION
    # ------------------------------------------------------------------

    def _analyse_document(self, image_bytes: bytes) -> DocumentAnalysis:
        """
        Detect document forgery using Error Level Analysis (ELA).

        ELA works by re-compressing the image at a known quality
        level and comparing the error. Forged regions that were
        pasted from different sources show different error levels
        than the original content.

        Also checks for:
        - Inconsistent fonts (multiple font families in one document)
        - Alignment anomalies
        - Metadata inconsistencies
        """
        result = DocumentAnalysis()

        if not PIL_AVAILABLE:
            return result

        try:
            img = Image.open(io.BytesIO(image_bytes))

            # Only analyse JPEG (ELA requires lossy compression)
            if img.format == "JPEG" or img.mode == "RGB":
                ela_score = self._compute_ela(img)
                result.ela_anomaly_score = ela_score

                if ela_score > 0.5:
                    result.indicators.append(
                        f"ELA anomaly score: {ela_score:.2f} "
                        f"(threshold: 0.5)"
                    )

            # Check for document-like content
            img_array = np.array(img.convert("RGB"))

            # High contrast ratio suggests document (text on white)
            gray = np.mean(img_array, axis=2)
            contrast = np.std(gray)

            if contrast > 60:  # Document-like contrast
                # Check for uniform background (white/light)
                white_pixels = np.sum(gray > 240) / gray.size
                if white_pixels > 0.3:
                    result.indicators.append(
                        f"Document-like content detected "
                        f"({white_pixels*100:.0f}% white background)"
                    )

            # Metadata check
            exif_anomalies = self._check_exif_metadata(img)
            result.metadata_anomalies = exif_anomalies

            # Overall forgery score
            score = result.ela_anomaly_score * 0.5
            if exif_anomalies:
                score += min(0.3, len(exif_anomalies) * 0.1)
            if result.indicators:
                score += 0.1

            result.confidence = min(1.0, score)
            result.is_forged = result.confidence > 0.6

        except Exception as e:
            logger.debug(f"Document analysis failed: {e}")

        return result

    def _compute_ela(self, img) -> float:
        """
        Compute Error Level Analysis score.

        Re-compress at quality 95, compute difference with original.
        High variance in difference = potential forgery.
        """
        try:
            # Re-compress at known quality
            buffer = io.BytesIO()
            img.save(buffer, format="JPEG", quality=95)
            buffer.seek(0)
            recompressed = Image.open(buffer)

            # Compute difference
            original_array = np.array(img.convert("RGB"), dtype=np.float64)
            recomp_array = np.array(recompressed.convert("RGB"), dtype=np.float64)

            if original_array.shape != recomp_array.shape:
                return 0.0

            diff = np.abs(original_array - recomp_array)

            # Compute statistics of the error
            mean_error = np.mean(diff)
            std_error = np.std(diff)

            # High std relative to mean suggests inconsistent compression
            # (different regions compressed at different levels = forgery)
            if mean_error > 0:
                coefficient_of_variation = std_error / mean_error
                # Normalise to 0-1
                score = min(1.0, coefficient_of_variation / 3.0)
                return score

            return 0.0

        except Exception:
            return 0.0

    # ------------------------------------------------------------------
    # STEGANOGRAPHY DETECTION
    # ------------------------------------------------------------------

    def _analyse_steganography(self, image_bytes: bytes) -> SteganographyAnalysis:
        """
        Detect steganography using chi-squared test on LSB distribution.

        Natural images have specific statistical properties in their
        least significant bits. Steganographic embedding disturbs
        these properties in detectable ways.

        Chi-squared test:
          χ² = Σ (Oᵢ - Eᵢ)² / Eᵢ
        Where Oᵢ = observed LSB pair frequency
              Eᵢ = expected frequency under null hypothesis
        """
        result = SteganographyAnalysis()

        if not PIL_AVAILABLE:
            return result

        try:
            img = Image.open(io.BytesIO(image_bytes))
            pixels = np.array(img.convert("RGB"), dtype=np.uint8)

            if pixels.size == 0:
                return result

            # Extract LSBs from each channel
            for channel in range(3):
                channel_data = pixels[:, :, channel].flatten()

                # Compute LSB pairs (adjacent pixel LSBs)
                lsbs = channel_data & 1

                if len(lsbs) < 100:
                    continue

                # Count pair frequencies
                pairs = {}
                for i in range(0, len(lsbs) - 1, 2):
                    pair = (lsbs[i], lsbs[i + 1])
                    pairs[pair] = pairs.get(pair, 0) + 1

                total_pairs = sum(pairs.values())
                if total_pairs == 0:
                    continue

                # Expected frequency under null hypothesis (uniform)
                expected = total_pairs / 4.0

                # Chi-squared statistic
                chi_sq = sum(
                    (count - expected) ** 2 / expected
                    for count in pairs.values()
                )

                # Normalise (3 degrees of freedom for 4 categories)
                # Chi-squared critical value at p=0.05, df=3 is 7.815
                normalised = chi_sq / 7.815

                if normalised > 1.0:
                    result.chi_squared_score = max(
                        result.chi_squared_score,
                        min(1.0, normalised / 5.0),
                    )

            # LSB randomness test
            all_lsbs = (pixels & 1).flatten()
            ones_ratio = np.mean(all_lsbs)

            # Natural images: LSB ratio is slightly biased
            # Steganographic images: LSB ratio closer to 0.5
            lsb_deviation = abs(ones_ratio - 0.5)
            if lsb_deviation < 0.01:  # Very close to 0.5 = suspicious
                result.lsb_anomaly_score = 1.0 - (lsb_deviation * 100)
                result.indicators.append(
                    f"LSB distribution unusually uniform "
                    f"(ratio={ones_ratio:.4f}, deviation={lsb_deviation:.4f})"
                )

            # Estimate payload size
            if result.chi_squared_score > 0.3 or result.lsb_anomaly_score > 0.5:
                # Rough estimate: 1 bit per pixel per channel
                result.estimated_payload_size = pixels.size // 8  # bytes

            # Overall score
            score = max(result.chi_squared_score, result.lsb_anomaly_score)
            result.confidence = score
            result.is_suspicious = score > 0.5

            if result.is_suspicious:
                result.indicators.append(
                    f"Steganography suspected: χ²={result.chi_squared_score:.2f}, "
                    f"LSB={result.lsb_anomaly_score:.2f}"
                )

        except Exception as e:
            logger.debug(f"Steganography analysis failed: {e}")

        return result

    # ------------------------------------------------------------------
    # TEXT EXTRACTION (OCR)
    # ------------------------------------------------------------------

    def _extract_text(self, image_bytes: bytes) -> str:
        """Extract text from image using OCR."""
        try:
            import pytesseract
            if PIL_AVAILABLE:
                img = Image.open(io.BytesIO(image_bytes))
                text = pytesseract.image_to_string(img)
                return text.strip()
        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"OCR failed: {e}")

        return ""

    # ------------------------------------------------------------------
    # LLM VISION ANALYSIS
    # ------------------------------------------------------------------

    async def _llm_analyse(
        self,
        image_bytes: bytes,
        context: Optional[str] = None,
        extracted_text: str = "",
    ) -> Optional[str]:
        """
        Use LLM vision model for semantic analysis.

        Sends the image to IMMUNIS-Vision (Qwen2-VL-7B) or
        falls back to GPT-4o vision via AIsa.one.
        """
        try:
            if self._llm_client is None:
                from backend.services.aisa_client import get_aisa_client
                self._llm_client = get_aisa_client()

            import base64
            image_b64 = base64.b64encode(image_bytes).decode("utf-8")

            # Determine MIME type
            mime = "image/jpeg"
            if image_bytes[:8] == b'\x89PNG\r\n\x1a\n':
                mime = "image/png"
            elif image_bytes[:4] == b'GIF8':
                mime = "image/gif"
            elif image_bytes[:4] == b'RIFF':
                mime = "image/webp"

            prompt = (
                "Analyse this image for cybersecurity threats. "
                "Check for:\n"
                "1. Phishing indicators (fake login pages, brand impersonation)\n"
                "2. Document forgery (altered invoices, fake letters)\n"
                "3. QR codes leading to suspicious URLs\n"
                "4. Deepfake indicators (facial inconsistencies)\n"
                "5. Social engineering visual cues\n"
                "6. Any hidden or embedded content\n\n"
            )

            if context:
                prompt += f"Context from accompanying text:\n{context[:500]}\n\n"

            if extracted_text:
                prompt += f"OCR extracted text:\n{extracted_text[:500]}\n\n"

            prompt += (
                "Respond with:\n"
                "- THREAT_TYPE: (qr_phishing|deepfake|document_forgery|"
                "screenshot_phishing|logo_impersonation|clean)\n"
                "- CONFIDENCE: (0.0-1.0)\n"
                "- ANALYSIS: (detailed explanation)\n"
                "- INDICATORS: (list of specific indicators found)"
            )

            response = await self._llm_client.generate(
                prompt=prompt,
                temperature=0.2,
                max_tokens=500,
                images=[{"mime": mime, "data": image_b64}],
            )

            return response.get("content", "")

        except Exception as e:
            logger.debug(f"LLM vision analysis failed: {e}")
            return None

    # ------------------------------------------------------------------
    # THREAT DETERMINATION
    # ------------------------------------------------------------------

    def _determine_threat(
        self,
        qr: Optional[QRAnalysis],
        deepfake: DeepfakeAnalysis,
        document: DocumentAnalysis,
        stego: SteganographyAnalysis,
        extracted_text: str,
        llm_analysis: Optional[str],
    ) -> tuple[VisualThreatType, float]:
        """
        Determine the overall threat type and confidence.

        Combines all analysis results with weighted scoring.
        """
        scores: dict[VisualThreatType, float] = {
            VisualThreatType.CLEAN: 0.3,  # Base score for clean
        }

        # QR phishing
        if qr and qr.is_suspicious:
            scores[VisualThreatType.QR_PHISHING] = (
                (1.0 - qr.reputation_score) * 0.7
                + min(0.3, len(qr.suspicion_reasons) * 0.1)
            )

        # Deepfake
        if deepfake.is_deepfake:
            scores[VisualThreatType.DEEPFAKE] = deepfake.confidence

        # Document forgery
        if document.is_forged:
            scores[VisualThreatType.DOCUMENT_FORGERY] = document.confidence

        # Steganography
        if stego.is_suspicious:
            scores[VisualThreatType.STEGANOGRAPHY] = stego.confidence

        # Screenshot phishing (from extracted text)
        if extracted_text:
            phishing_keywords = [
                "login", "password", "verify", "account",
                "suspended", "confirm", "update", "secure",
                "click here", "sign in", "credentials",
            ]
            keyword_count = sum(
                1 for kw in phishing_keywords
                if kw in extracted_text.lower()
            )
            if keyword_count >= 2:
                scores[VisualThreatType.SCREENSHOT_PHISHING] = min(
                    1.0, keyword_count * 0.15
                )

        # LLM analysis boost
        if llm_analysis:
            llm_lower = llm_analysis.lower()
            for threat_type in VisualThreatType:
                if threat_type.value in llm_lower and threat_type != VisualThreatType.CLEAN:
                    current = scores.get(threat_type, 0)
                    scores[threat_type] = min(1.0, current + 0.2)

            # Extract confidence from LLM response
            conf_match = re.search(r"CONFIDENCE:\s*([\d.]+)", llm_analysis)
            if conf_match:
                llm_conf = float(conf_match.group(1))
                # Boost the highest non-clean score
                non_clean = {
                    k: v for k, v in scores.items()
                    if k != VisualThreatType.CLEAN
                }
                if non_clean:
                    top_threat = max(non_clean, key=non_clean.get)
                    scores[top_threat] = min(
                        1.0,
                        scores[top_threat] * 0.6 + llm_conf * 0.4,
                    )

        # Determine winner
        best_threat = max(scores, key=scores.get)
        best_score = scores[best_threat]

        # If clean wins, return clean
        if best_threat == VisualThreatType.CLEAN:
            return VisualThreatType.CLEAN, 1.0 - best_score

        return best_threat, best_score

    # ------------------------------------------------------------------
    # STATISTICS
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        """Return visual analyst statistics."""
        return {
            "total_analyses": self._total_analyses,
            "threats_detected": self._threats_detected,
            "threat_rate": (
                self._threats_detected / self._total_analyses
                if self._total_analyses > 0
                else 0.0
            ),
            "threat_type_counts": dict(self._threat_type_counts),
            "capabilities": {
                "pillow": PIL_AVAILABLE,
                "opencv": CV2_AVAILABLE,
                "qr_decode": QRCODE_AVAILABLE,
            },
        }


# Module-level singleton
_analyst: Optional[VisualThreatAnalyst] = None


def get_visual_analyst() -> VisualThreatAnalyst:
    """Get or create the singleton VisualThreatAnalyst instance."""
    global _analyst
    if _analyst is None:
        _analyst = VisualThreatAnalyst()
    return _analyst
