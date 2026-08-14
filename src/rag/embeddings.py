"""Embedding backends for the log-search index.

Two backends, chosen by ``SOC_EMBEDDING_BACKEND``:

``tfidf`` (default)
    A dependency-free, deterministic TF-IDF vectoriser fitted on the log
    corpus.  Chosen as the default because it needs no model download, produces
    identical results on every machine, and keeps the demo fully offline.
    Be honest about what it is: this is **lexical** retrieval projected into a
    vector space, not semantic embedding.  It matches "powershell encoded
    command" to a line containing those terms; it will not reliably match
    "obfuscated script execution" to the same line.

``ollama``
    A real embedding model (default ``nomic-embed-text``) served by the local
    Ollama instance, giving genuine semantic recall.  Requires
    ``ollama pull nomic-embed-text``.  Switch with ``SOC_EMBEDDING_BACKEND=ollama``.

Both are local-only: no text leaves the host.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Protocol, runtime_checkable

_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9._\\/:-]*")
_SPLIT_RE = re.compile(r"[._\\/:-]+")

# Very common log/English filler that adds noise without discriminating power.
_STOPWORDS = frozenset(
    {
        "the", "a", "an", "and", "or", "of", "to", "for", "from", "in", "on",
        "with", "by", "is", "was", "are", "were", "be", "been", "at", "as",
        "that", "this", "it", "its", "true", "false", "null", "none",
    }
)


@runtime_checkable
class EmbeddingBackend(Protocol):
    """Minimal embedding interface used by the vector store."""

    dimensions: int

    def embed(self, texts: list[str]) -> list[list[float]]: ...

    @property
    def name(self) -> str: ...


@runtime_checkable
class FittableBackend(Protocol):
    """Backends that must see the corpus before they can embed."""

    def fit(self, texts: list[str]) -> None: ...


def tokenize(text: str) -> list[str]:
    """Lowercase tokens, their sub-tokens, and adjacent bigrams.

    Log text is full of compound identifiers -- ``powershell.exe``,
    ``vssadmin``, ``sso-login-verify.example``, ``HKCU\\Software\\...``.  A
    naive split would make the query "powershell encoded command" fail to match
    a line containing "powershell.exe", so each compound token is emitted both
    whole and split into its parts.

    Bigrams over the base stream give word-order sensitivity: with IDF
    weighting a rare bigram such as ``delete_shadows`` becomes a very strong
    match signal.
    """
    raw = [token for token in _TOKEN_RE.findall(text.lower()) if len(token) > 1]

    tokens: list[str] = []
    for token in raw:
        if token not in _STOPWORDS:
            tokens.append(token)
        parts = [part for part in _SPLIT_RE.split(token) if len(part) > 1]
        if len(parts) > 1:
            tokens.extend(part for part in parts if part not in _STOPWORDS)

    tokens.extend(f"{a}_{b}" for a, b in zip(raw, raw[1:], strict=False))
    return tokens


class TfidfEmbedding:
    """Deterministic TF-IDF vectoriser fitted on the corpus.

    Vectors are L2-normalised, so a dot product between two of them is exactly
    cosine similarity -- which is what both ChromaDB and the in-memory fallback
    use for ranking.
    """

    def __init__(self) -> None:
        self.vocabulary: dict[str, int] = {}
        self.idf: list[float] = []
        self.dimensions = 0
        self._fitted = False

    @property
    def name(self) -> str:
        return f"tfidf-{self.dimensions}"

    def fit(self, texts: list[str]) -> None:
        """Build the vocabulary and inverse document frequencies."""
        document_frequency: Counter[str] = Counter()
        for text in texts:
            document_frequency.update(set(tokenize(text)))

        total_documents = max(1, len(texts))
        # Terms appearing in every document carry no signal; terms appearing
        # once are usually the most discriminating (a hash, an IP, a filename).
        self.vocabulary = {
            term: index
            for index, term in enumerate(sorted(document_frequency))
            if document_frequency[term] < total_documents
        }
        # Re-index after filtering so indices stay contiguous.
        self.vocabulary = {term: index for index, term in enumerate(sorted(self.vocabulary))}
        self.dimensions = len(self.vocabulary)

        # Smoothed IDF, as in scikit-learn: ln((1+N)/(1+df)) + 1.
        self.idf = [0.0] * self.dimensions
        for term, index in self.vocabulary.items():
            self.idf[index] = math.log((1.0 + total_documents) / (1.0 + document_frequency[term])) + 1.0

        self._fitted = True

    def _embed_one(self, text: str) -> list[float]:
        vector = [0.0] * self.dimensions
        if self.dimensions == 0:
            return vector

        counts = Counter(tokenize(text))
        for term, count in counts.items():
            index = self.vocabulary.get(term)
            if index is None:
                continue  # Out-of-vocabulary terms are ignored, as is standard.
            vector[index] = (1.0 + math.log(count)) * self.idf[index]

        norm = math.sqrt(sum(value * value for value in vector))
        if norm > 0:
            vector = [value / norm for value in vector]
        return vector

    def embed(self, texts: list[str]) -> list[list[float]]:
        if not self._fitted:
            raise RuntimeError("TfidfEmbedding.fit() must be called before embed()")
        return [self._embed_one(text) for text in texts]


class OllamaEmbedding:
    """Embedding backend backed by a locally served Ollama embedding model."""

    def __init__(self, model: str, base_url: str, dimensions: int = 768, timeout: int = 60) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.dimensions = dimensions
        self.timeout = timeout

    @property
    def name(self) -> str:
        return f"ollama-{self.model}"

    def embed(self, texts: list[str]) -> list[list[float]]:
        import httpx

        vectors: list[list[float]] = []
        with httpx.Client(timeout=self.timeout) as client:
            for text in texts:
                response = client.post(
                    f"{self.base_url}/api/embeddings",
                    json={"model": self.model, "prompt": text},
                )
                response.raise_for_status()
                embedding = response.json().get("embedding") or []
                vectors.append([float(value) for value in embedding])

        if vectors:
            self.dimensions = len(vectors[0])
        return vectors


def get_embedding_backend() -> EmbeddingBackend:
    """Build the embedding backend named by settings."""
    from src.config import get_settings

    settings = get_settings()

    if settings.embedding_backend == "ollama":
        return OllamaEmbedding(
            model=settings.ollama_embedding_model,
            base_url=settings.ollama_base_url,
            timeout=settings.llm_timeout_seconds,
        )
    return TfidfEmbedding()
