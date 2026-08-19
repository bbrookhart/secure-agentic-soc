"""Semantic search over the historical log corpus (ChromaDB).

Security posture: everything returned by this module is **untrusted**.  Log
lines are attacker-influenceable (an adversary who can write to a log can write
whatever text they like into it), so search results are sanitised by the tool
layer before they are allowed anywhere near a prompt.  See
``src/tools/log_search.py`` and ``src/security/sanitizer.py``.

The index is content-addressed: the collection name embeds a hash of the corpus
plus the embedding backend, so changing either transparently rebuilds rather
than silently serving a stale index.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from src.rag.embeddings import EmbeddingBackend, FittableBackend, get_embedding_backend


@dataclass(frozen=True)
class LogDocument:
    """One indexed log line."""

    log_id: str
    timestamp: str
    host: str
    source: str
    message: str

    def searchable_text(self) -> str:
        return f"{self.host} {self.source} {self.message}"


@dataclass(frozen=True)
class SearchResult:
    """A scored search hit."""

    document: LogDocument
    relevance: float


def _parse_timestamp(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _apply_scope(
    results: list[SearchResult],
    *,
    around: str | None,
    window_hours: int,
    hosts: Sequence[str],
) -> list[SearchResult]:
    """Drop hits outside the incident's host set or time window.

    A hit with an unparseable timestamp is *kept*: the point is to remove
    confidently-irrelevant lines, not to discard evidence because its clock
    format was unexpected.
    """
    host_set = {h.strip().lower() for h in hosts if h and h.strip()}
    centre = _parse_timestamp(around) if around else None
    span = timedelta(hours=window_hours)

    kept: list[SearchResult] = []
    for result in results:
        if host_set and result.document.host.strip().lower() not in host_set:
            continue
        if centre is not None:
            moment = _parse_timestamp(result.document.timestamp)
            if moment is not None and abs(moment - centre) > span:
                continue
        kept.append(result)
    return kept


def load_corpus(path: Path | Sequence[Path]) -> list[LogDocument]:
    """Read one or more JSONL log corpora, skipping malformed lines.

    Several paths are supported so hand-authored logs and generated scenario
    logs can live in separate files. Keeping them apart matters: a generator
    bug that corrupts its output must not be able to damage the corpus the
    existing eval cases depend on.
    """
    if not isinstance(path, Path):
        documents: list[LogDocument] = []
        for item in path:
            documents.extend(load_corpus(item))
        return documents

    documents = []
    if not path.exists():
        return documents

    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record: dict[str, Any] = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not record.get("message"):
                continue
            documents.append(
                LogDocument(
                    log_id=str(record.get("log_id", f"LOG-{len(documents):04d}")),
                    timestamp=str(record.get("timestamp", "")),
                    host=str(record.get("host", "")),
                    source=str(record.get("source", "")),
                    message=str(record["message"]),
                )
            )
    return documents


def _corpus_fingerprint(documents: list[LogDocument]) -> str:
    digest = hashlib.sha256()
    for document in documents:
        digest.update(document.log_id.encode("utf-8"))
        digest.update(document.message.encode("utf-8"))
    return digest.hexdigest()[:12]


def _cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=False))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


class LogVectorStore:
    """Vector index over the log corpus.

    Prefers ChromaDB with on-disk persistence.  If Chroma cannot be loaded
    (missing wheel, read-only filesystem, sandboxed CI), it degrades to an
    in-memory brute-force cosine search over the same embeddings rather than
    failing the run -- a SOC tool that dies because its cache is unavailable is
    worse than one that runs a little slower.
    """

    def __init__(
        self,
        corpus_path: Path | Sequence[Path],
        persist_dir: Path | None = None,
        embedding: EmbeddingBackend | None = None,
    ) -> None:
        self.corpus_path = corpus_path
        self.persist_dir = persist_dir
        self.embedding = embedding or get_embedding_backend()
        self.documents = load_corpus(corpus_path)
        self._by_id = {document.log_id: document for document in self.documents}
        self._collection: Any | None = None
        self._fallback_vectors: list[list[float]] | None = None
        self.backend_name = "uninitialised"
        self._initialise()

    # --- Index construction ---------------------------------------------
    def _initialise(self) -> None:
        if not self.documents:
            self.backend_name = "empty"
            self._fallback_vectors = []
            return

        # Fitted backends (TF-IDF) must see the whole corpus before embedding.
        if isinstance(self.embedding, FittableBackend):
            self.embedding.fit([document.searchable_text() for document in self.documents])

        if self.persist_dir is not None and self._try_chroma():
            return
        self._build_fallback()

    def _try_chroma(self) -> bool:
        persist_dir = self.persist_dir
        if persist_dir is None:
            return False

        try:
            import chromadb
            from chromadb.config import Settings as ChromaSettings
        except Exception:  # noqa: BLE001 - any import failure means "use fallback"
            return False

        try:
            fingerprint = _corpus_fingerprint(self.documents)
            collection_name = f"soc_logs_{self.embedding.name.replace('.', '_')}_{fingerprint}"[:60]

            persist_dir.mkdir(parents=True, exist_ok=True)
            client = chromadb.PersistentClient(
                path=str(persist_dir),
                settings=ChromaSettings(anonymized_telemetry=False, allow_reset=False),
            )

            existing = {c.name for c in client.list_collections()}
            collection = client.get_or_create_collection(
                name=collection_name,
                metadata={"hnsw:space": "cosine"},
            )

            if collection_name not in existing or collection.count() != len(self.documents):
                texts = [document.searchable_text() for document in self.documents]
                collection.upsert(
                    ids=[document.log_id for document in self.documents],
                    # Chroma's stub types expect numpy arrays; plain float lists
                    # are accepted at runtime and keep numpy out of our code.
                    embeddings=self.embedding.embed(texts),  # type: ignore[arg-type]
                    documents=[document.message for document in self.documents],
                    metadatas=[
                        {
                            "timestamp": document.timestamp,
                            "host": document.host,
                            "source": document.source,
                        }
                        for document in self.documents
                    ],
                )

            self._collection = collection
            self.backend_name = f"chromadb:{self.embedding.name}"
            return True
        except Exception:  # noqa: BLE001 - degrade rather than fail the investigation
            self._collection = None
            return False

    def _build_fallback(self) -> None:
        texts = [document.searchable_text() for document in self.documents]
        self._fallback_vectors = self.embedding.embed(texts)
        self.backend_name = f"in-memory:{self.embedding.name}"

    # --- Query -----------------------------------------------------------
    def search(
        self,
        query: str,
        limit: int = 5,
        *,
        around: str | None = None,
        window_hours: int = 72,
        hosts: Sequence[str] = (),
    ) -> list[SearchResult]:
        """Return the ``limit`` most relevant log lines for ``query``.

        ``around``/``window_hours`` and ``hosts`` scope the search before
        relevance is considered. Both matter because relevance here is lexical:
        a line from an unrelated host a week later shares vocabulary with the
        query just as readily as the contemporaneous one, and will outrank it
        if it happens to use more of the same words. Scoping first makes
        "relevant" mean *relevant to this incident* rather than *wordy in the
        same way*.
        """
        query = (query or "").strip()
        if not query or not self.documents:
            return []
        limit = max(1, min(limit, 25))

        # Over-fetch when scoping, so filtering does not silently return fewer
        # results than asked for.
        scoped = bool(around) or bool(hosts)
        fetch = min(25, limit * 5) if scoped else limit

        if self._collection is not None:
            try:
                results = self._search_chroma(query, fetch)
            except Exception:  # noqa: BLE001 - one bad query must not kill the store
                self._build_fallback()
                results = self._search_fallback(query, fetch)
        else:
            if self._fallback_vectors is None:
                self._build_fallback()
            results = self._search_fallback(query, fetch)

        if scoped:
            results = _apply_scope(results, around=around, window_hours=window_hours, hosts=hosts)
        return results[:limit]

    def _search_chroma(self, query: str, limit: int) -> list[SearchResult]:
        query_vector = self.embedding.embed([query])[0]
        response = self._collection.query(  # type: ignore[union-attr]
            query_embeddings=[query_vector],
            n_results=min(limit, len(self.documents)),
        )

        ids = (response.get("ids") or [[]])[0]
        distances = (response.get("distances") or [[]])[0]

        results: list[SearchResult] = []
        for log_id, distance in zip(ids, distances, strict=False):
            document = self._by_id.get(log_id)
            if document is None:
                continue
            # Chroma cosine distance is in [0, 2]; map to a [0, 1] relevance.
            relevance = max(0.0, min(1.0, 1.0 - float(distance)))
            # Drop non-matches: with lexical vectors a zero score means the
            # query shared no vocabulary with the document, and padding the
            # results with noise actively misleads the hunter agent.
            if relevance > 0.0:
                results.append(SearchResult(document=document, relevance=relevance))
        return results

    def _search_fallback(self, query: str, limit: int) -> list[SearchResult]:
        query_vector = self.embedding.embed([query])[0]
        scored = [
            SearchResult(
                document=document,
                relevance=max(0.0, min(1.0, _cosine(query_vector, vector))),
            )
            for document, vector in zip(self.documents, self._fallback_vectors or [], strict=False)
        ]
        scored.sort(key=lambda result: result.relevance, reverse=True)
        return [result for result in scored[:limit] if result.relevance > 0.0]

    def stats(self) -> dict[str, Any]:
        return {
            "backend": self.backend_name,
            "documents": len(self.documents),
            "corpus_path": str(self.corpus_path),
        }


_store: LogVectorStore | None = None


def get_log_store() -> LogVectorStore:
    """Process-wide vector store singleton (indexing is not free)."""
    global _store
    if _store is None:
        from src.config import get_settings

        settings = get_settings()
        settings.ensure_dirs()
        _store = LogVectorStore(
            corpus_path=[settings.log_corpus_path, settings.generated_log_corpus_path],
            persist_dir=settings.chroma_dir,
        )
    return _store


def set_log_store(store: LogVectorStore | None) -> None:
    """Override the singleton (test hook)."""
    global _store
    _store = store
