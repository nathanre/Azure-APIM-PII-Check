"""Safe text chunking with overlapping windows.

Large inputs are split into overlapping windows so that sensitive entities
straddling a boundary are still fully contained in at least one chunk. Each
returned chunk records its absolute start offset in the original text so that
entity offsets can be re-based onto the source document.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class TextChunk:
    """A window of text plus its absolute start offset in the source."""

    text: str
    offset: int


def chunk_text(
    text: str,
    max_chunk_chars: int,
    overlap_chars: int,
) -> List[TextChunk]:
    """Split ``text`` into overlapping windows.

    Args:
        text: The source text to chunk.
        max_chunk_chars: Maximum characters per chunk. Must be > 0.
        overlap_chars: Characters of overlap between consecutive chunks.
            Clamped to ``max_chunk_chars - 1`` to guarantee forward progress.

    Returns:
        A list of :class:`TextChunk`. Empty input yields an empty list.
    """
    if text is None:
        return []
    if max_chunk_chars <= 0:
        raise ValueError("max_chunk_chars must be positive")

    length = len(text)
    if length == 0:
        return []
    if length <= max_chunk_chars:
        return [TextChunk(text=text, offset=0)]

    overlap = max(0, min(overlap_chars, max_chunk_chars - 1))
    step = max_chunk_chars - overlap

    chunks: List[TextChunk] = []
    start = 0
    while start < length:
        end = min(start + max_chunk_chars, length)
        chunks.append(TextChunk(text=text[start:end], offset=start))
        if end >= length:
            break
        start += step
    return chunks
