"""IMMUNIS ACIN — Output Validator

Pydantic V2 strict schema enforcement for LLM outputs (LLM05).
Validates every output before downstream use.
"""

import json
from typing import Any, Type, TypeVar, get_origin, get_args
from pydantic import BaseModel, ValidationError
from pydantic.json import pydantic_encoder

from backend.models.schemas import (
    Antibody,
    ThreatAnalysis,
    SurpriseResult,
    VisualAnalysis,
    AntibodyVerification,
    ArbiterDecision,
    ActuarialMetrics,
    EpidemiologicalState,
    GameTheoryAllocation,
)

T = TypeVar("T", bound=BaseModel)


class OutputValidator:
    """Strict output validation using Pydantic V2"""

    def __init__(self):
        """Initialise validator with known schemas"""
        self.schema_map = {
            "Antibody": Antibody,
            "ThreatAnalysis": ThreatAnalysis,
            "SurpriseResult": SurpriseResult,
            "VisualAnalysis": VisualAnalysis,
            "AntibodyVerification": AntibodyVerification,
            "ArbiterDecision": ArbiterDecision,
            "ActuarialMetrics": ActuarialMetrics,
            "EpidemiologicalState": EpidemiologicalState,
            "GameTheoryAllocation": GameTheoryAllocation,
        }

    def validate(
        self,
        output: str | dict[str, Any],
        schema_name: str,
        strict: bool = True
    ) -> tuple[bool, BaseModel | None, str]:
        """
        Validate LLM output against Pydantic schema.

        Args:
            output: Raw output from LLM (string or dict)
            schema_name: Name of schema to validate against
            strict: Use strict mode validation

        Returns:
            Tuple of (is_valid, validated_model, error_message)
        """
        schema = self.schema_map.get(schema_name)
        if schema is None:
            return False, None, f"Unknown schema: {schema_name}"

        # Parse string to dict if needed
        if isinstance(output, str):
            try:
                output_dict = json.loads(output)
            except json.JSONDecodeError as e:
                return False, None, f"Invalid JSON: {e}"
        else:
            output_dict = output

        # Validate with Pydantic
        try:
            if strict:
                validated = schema.model_validate(output_dict, strict=True)
            else:
                validated = schema.model_validate(output_dict)
            return True, validated, ""
        except ValidationError as e:
            error_msg = self._format_validation_error(e)
            return False, None, error_msg
        except Exception as e:
            return False, None, f"Validation error: {e}"

    def validate_with_fallback(
        self,
        output: str,
        schema_name: str,
        fallback_value: Any = None
    ) -> BaseModel:
        """
        Validate with fallback value on failure.

        Args:
            output: Raw output from LLM
            schema_name: Name of schema to validate against
            fallback_value: Value to use if validation fails

        Returns:
            Validated model or fallback
        """
        is_valid, validated, error = self.validate(output, schema_name)
        if is_valid:
            return validated
        if fallback_value is not None:
            return fallback_value
        raise ValueError(f"Output validation failed: {error}")

    def extract_json_from_text(self, text: str) -> str:
        """
        Extract JSON from LLM text output (handles markdown code blocks).

        Args:
            text: Raw LLM output that may contain markdown

        Returns:
            Extracted JSON string
        """
        # Try to find JSON in markdown code blocks
        patterns = [
            r"```json\s*(.*?)\s*```",  # ```json ... ```
            r"```\s*(.*?)\s*```",  # ``` ... ```
            r"\{.*\}",  # Direct JSON object
        ]

        for pattern in patterns:
            match = self._find_first_match(text, pattern, re.DOTALL)
            if match:
                return match.strip()

        # If no pattern matched, return original
        return text.strip()

    def _find_first_match(self, text: str, pattern: str, flags: int = 0) -> str | None:
        """Find first match of pattern in text"""
        import re
        matches = re.findall(pattern, text, flags)
        return matches[0] if matches else None

    def _format_validation_error(self, error: ValidationError) -> str:
        """Format Pydantic validation error for logging"""
        errors = error.errors()
        formatted = []
        for err in errors:
            loc = " -> ".join(str(l) for l in err["loc"])
            formatted.append(f"{loc}: {err['msg']}")
        return "; ".join(formatted)

    def sanitise_output(self, output: str) -> str:
        """
        Basic output sanitisation (LLM05).

        Args:
            output: Raw LLM output

        Returns:
            Sanitised output
        """
        # Remove potential system prompt leakage
        if "SYSTEM:" in output or "system prompt:" in output.lower():
            output = output.split("SYSTEM:")[0]
            output = output.split("system prompt:")[0]

        # Remove instruction leakage
        if "INSTRUCTION:" in output or "instruction:" in output.lower():
            output = output.split("INSTRUCTION:")[0]
            output = output.split("instruction:")[0]

        # Trim whitespace
        output = output.strip()

        return output

    def check_for_hallucination(
        self,
        output: dict[str, Any],
        ground_truth: dict[str, Any],
        required_fields: list[str]
    ) -> tuple[bool, list[str]]:
        """
        Cross-reference output claims against ground truth (hallucination detection).

        Args:
            output: LLM output as dict
            ground_truth: Known ground truth
            required_fields: Fields that must match ground truth

        Returns:
            Tuple of (is_consistent, inconsistent_fields)
        """
        inconsistent = []
        for field in required_fields:
            if field in output and field in ground_truth:
                if output[field] != ground_truth[field]:
                    inconsistent.append(field)
        return len(inconsistent) == 0, inconsistent


# Global instance
output_validator = OutputValidator()
