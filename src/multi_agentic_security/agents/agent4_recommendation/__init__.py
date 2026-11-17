"""Agent 4: remediation recommendation (D-047 d, D-062).

Variants: ``R0`` (deterministic rules), ``LLM-G`` (LLM with the dependency's evidence
records) and ``LLM-U`` (LLM with finding names only), all behind ``recommend``. LLMs are
reached only through the provider-independent ``LLMClient`` interface.
"""

from .llm import (
    ENV_VARS, FileResponseStore, LLMClient, LLMError, LLMOptions, LLMRequest, LLMResponse, LLMTimeout,
    MemoryResponseStore, RecordedLLMClient,
)
from .packet import VARIANTS
from .prompt import PROMPT_VERSION
from .recommend import STAGE_VERSION, recommend
from .rules import RULES_VERSION

__all__ = ["ENV_VARS", "FileResponseStore", "LLMClient", "LLMError", "LLMOptions", "LLMRequest", "LLMResponse",
           "LLMTimeout", "MemoryResponseStore", "PROMPT_VERSION", "RULES_VERSION", "RecordedLLMClient",
           "STAGE_VERSION", "VARIANTS", "recommend"]
