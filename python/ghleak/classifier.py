"""Commit message classifier — regex-first, AI-fallback.

AI backends supported:
  Provider     SDK       Auth         Endpoint
  ───────────────────────────────────────────────────────────
  openai       httpx     Bearer key   OpenAI-compatible /v1/chat/completions
                                     → Ollama, vLLM, LocalAI, etc.
  gemini       google-genai SDK      API key in constructor
  anthropic    httpx     x-api-key   /v1/messages
  custom       httpx     Bearer key  any OpenAI-compatible endpoint

  Each backend works with or without an API key (omit key → Ollama/local).
"""

from __future__ import annotations

import json
import logging
import re
from typing import Literal

import httpx

from . import config

log = logging.getLogger(__name__)

Classification = Literal["suspicious", "clean", "ambiguous"]


# ── AI Backends ───────────────────────────────────────────────────

class LLMBackend:
    """Abstract LLM backend. Subclasses implement _call()."""

    def classify(self, message: str) -> Classification:
        prompt = config.ONE_SHOT_PROMPT.format(commit_message=message)
        try:
            text = self._call(prompt).strip().lower()
            return "suspicious" if text.startswith("true") else "clean"
        except Exception as exc:
            log.warning("LLM classify failed: %s", exc)
            return "ambiguous"

    def classify_batch(self, messages: list[str]) -> dict[int, Classification]:
        batch_text = "\n---\n".join(f"[{i}] {msg}" for i, msg in enumerate(messages))
        prompt = config.BATCH_PROMPT.format(messages=batch_text)
        try:
            text = self._call(prompt).strip()
            text = re.sub(r"^```(?:json)?\s*|```\s*$", "", text).strip()
            data = json.loads(text)
            return {int(k): ("suspicious" if v else "clean") for k, v in data.items()}
        except Exception as exc:
            log.warning("LLM batch classify failed: %s", exc)
            return {i: "ambiguous" for i in range(len(messages))}

    def _call(self, prompt: str) -> str:
        raise NotImplementedError


class OpenAIBackend(LLMBackend):
    """OpenAI-compatible (also Ollama, vLLM, LocalAI, etc.).

    With key → Bearer auth. Without key → no auth (Ollama default).
    """

    def __init__(
        self,
        endpoint: str = config.DEFAULT_LLM_ENDPOINT,
        api_key: str | None = None,
        model: str = config.DEFAULT_LLM_MODEL,
    ) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.api_key = api_key
        self.model = model
        self._client = httpx.Client(timeout=30)

    def _call(self, prompt: str) -> str:
        headers = {"User-Agent": config.USER_AGENT}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        body = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 64,
            "temperature": 0,
        }
        resp = self._client.post(self.endpoint, headers=headers, json=body, timeout=30)
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]


class GeminiBackend(LLMBackend):
    """Google Gemini native via google-genai SDK.

    Requires: pip install google-genai
    Works only with an API key (Gemini does not allow keyless).
    """

    def __init__(self, api_key: str, model: str = "gemini-2.5-flash-lite") -> None:
        self.api_key = api_key
        self.model = model
        self._client = None

    def _ensure_client(self):
        if self._client is None:
            try:
                from google import genai
                self._client = genai.Client(api_key=self.api_key)
            except ImportError:
                raise RuntimeError(
                    "google-genai not installed. Run: pip install google-genai"
                )
        return self._client

    def _call(self, prompt: str) -> str:
        client = self._ensure_client()
        resp = client.models.generate_content(model=self.model, contents=prompt)
        return resp.text


class AnthropicBackend(LLMBackend):
    """Anthropic Claude via their Messages API.

    With key → x-api-key header. Without key → error (Anthropic requires key).
    """

    def __init__(self, api_key: str | None = None, model: str = "claude-3-5-haiku-latest") -> None:
        self.api_key = api_key
        self.model = model
        self._client = httpx.Client(timeout=60)

    def _call(self, prompt: str) -> str:
        if not self.api_key:
            raise RuntimeError("Anthropic requires an API key (set --llm-key or LLM_API_KEY)")
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        body = {
            "model": self.model,
            "max_tokens": 64,
            "messages": [{"role": "user", "content": prompt}],
        }
        resp = self._client.post(
            "https://api.anthropic.com/v1/messages",
            headers=headers, json=body, timeout=60,
        )
        resp.raise_for_status()
        return resp.json()["content"][0]["text"]


BACKEND_REGISTRY: dict[str, type[LLMBackend]] = {
    "openai": OpenAIBackend,
    "gemini": GeminiBackend,
    "anthropic": AnthropicBackend,
    "custom": OpenAIBackend,
}


def build_llm_backend(
    provider: str,
    endpoint: str | None = None,
    api_key: str | None = None,
    model: str | None = None,
) -> LLMBackend | None:
    """Factory: create the right backend from provider name + config."""
    provider = provider.lower()
    cls = BACKEND_REGISTRY.get(provider)

    if provider == "gemini":
        if not api_key:
            log.warning("Gemini requires an API key. AI fallback disabled.")
            return None
        return cls(api_key=api_key, model=model or config.DEFAULT_LLM_MODEL)

    if provider == "anthropic":
        if not api_key:
            log.warning("Anthropic requires an API key. AI fallback disabled.")
            return None
        return cls(api_key=api_key, model=model or "claude-3-5-haiku-latest")

    if provider in ("openai", "custom"):
        ep = endpoint or config.DEFAULT_LLM_ENDPOINT
        mdl = model or config.DEFAULT_LLM_MODEL
        return cls(endpoint=ep, api_key=api_key, model=mdl)

    log.warning("Unknown LLM provider: %s. AI fallback disabled.", provider)
    return None


# ── Commit Classifier ─────────────────────────────────────────────

class CommitClassifier:
    """Two-tier regex classifier with optional LLM fallback for ambiguous."""

    def __init__(
        self,
        rules: dict | None = None,
        llm_backend: LLMBackend | None = None,
        cache: dict[str, Classification] | None = None,
    ):
        self.rules = rules or {
            "high_verbs": set(config.HIGH_CONFIDENCE_ACTION_VERBS),
            "high_nouns": set(config.HIGH_CONFIDENCE_OBJECT_NOUNS),
            "broad_verbs": set(config.BROAD_ACTION_VERBS),
            "broad_nouns": set(config.BROAD_OBJECT_NOUNS),
        }
        self.llm = llm_backend
        self.cache = cache or {}
        self._stats = {"regex_tier1": 0, "regex_tier2": 0, "patterns": 0, "llm": 0, "cache_hit": 0}

    def classify(self, message: str) -> Classification:
        if not message or not message.strip():
            return "clean"
        msg_key = message.strip().lower()
        if msg_key in self.cache:
            self._stats["cache_hit"] += 1
            return self.cache[msg_key]
        result = self._classify_core(message)
        self.cache[msg_key] = result
        return result

    def _classify_core(self, message: str) -> Classification:
        msg_lower = message.lower()

        for pat in config.SECRET_REMOVAL_PATTERNS + config.GIT_CRED_SWEEP_PATTERNS:
            if pat.search(msg_lower):
                self._stats["patterns"] += 1
                return "suspicious"

        words = set(self._tokenize(msg_lower))
        if words & self.rules["high_verbs"] and words & self.rules["high_nouns"]:
            self._stats["regex_tier1"] += 1
            return "suspicious"

        if words & self.rules["broad_verbs"] and words & self.rules["broad_nouns"]:
            self._stats["regex_tier2"] += 1
            return "suspicious"

        if self.llm is not None:
            self._stats["llm"] += 1
            return self.llm.classify(message)

        return "clean"

    @staticmethod
    def _tokenize(text: str) -> list[str]:
        return re.findall(r"[a-z0-9_.&!#$%]+", text)

    def stats(self) -> dict:
        return dict(self._stats)


class BatchClassifier(CommitClassifier):
    def classify_batch(self, messages: list[str]) -> list[Classification]:
        results: list[Classification | None] = [None] * len(messages)
        ambiguous_queue: list[tuple[int, str]] = []

        for i, msg in enumerate(messages):
            if not msg or not msg.strip():
                results[i] = "clean"
                continue

            key = msg.strip().lower()
            if key in self.cache:
                self._stats["cache_hit"] += 1
                results[i] = self.cache[key]
                continue

            # Run regex tiers locally to avoid single LLM calls
            is_suspicious = False
            for pat in config.SECRET_REMOVAL_PATTERNS + config.GIT_CRED_SWEEP_PATTERNS:
                if pat.search(key):
                    self._stats["patterns"] += 1
                    is_suspicious = True
                    break

            if not is_suspicious:
                words = set(self._tokenize(key))
                if words & self.rules["high_verbs"] and words & self.rules["high_nouns"]:
                    self._stats["regex_tier1"] += 1
                    is_suspicious = True
                elif words & self.rules["broad_verbs"] and words & self.rules["broad_nouns"]:
                    self._stats["regex_tier2"] += 1
                    is_suspicious = True

            if is_suspicious:
                results[i] = "suspicious"
                self.cache[key] = "suspicious"
            else:
                ambiguous_queue.append((i, msg))

        # Send ALL ambiguous messages to the LLM backend in one shot
        if ambiguous_queue and self.llm is not None:
            llm_msgs = [msg for _, msg in ambiguous_queue]
            batch_results = self.llm.classify_batch(llm_msgs)

            for list_idx, (orig_idx, msg) in enumerate(ambiguous_queue):
                res = batch_results.get(list_idx, "ambiguous")
                final_res: Classification = "suspicious" if res == "suspicious" else "clean"
                results[orig_idx] = final_res
                self.cache[msg.strip().lower()] = final_res
                self._stats["llm"] += 1
        else:
            for idx, msg in ambiguous_queue:
                results[idx] = "clean"
                self.cache[msg.strip().lower()] = "clean"

        return [r if r is not None else "clean" for r in results]
