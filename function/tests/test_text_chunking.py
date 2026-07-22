"""Tests for the text chunking utility."""

import pytest

from src.utils.chunking import TextChunk, chunk_text


def test_empty_text_returns_no_chunks():
    assert chunk_text("", 100, 10) == []


def test_short_text_returns_single_chunk():
    chunks = chunk_text("hello world", 100, 10)
    assert chunks == [TextChunk(text="hello world", offset=0)]


def test_text_is_split_into_overlapping_windows():
    text = "abcdefghij"  # 10 chars
    chunks = chunk_text(text, max_chunk_chars=4, overlap_chars=2)
    # step = 4 - 2 = 2 -> offsets 0,2,4,6 (offset 6 reaches the end)
    assert [c.offset for c in chunks] == [0, 2, 4, 6]
    assert chunks[0].text == "abcd"
    assert chunks[1].text == "cdef"
    assert chunks[-1].text == "ghij"


def test_chunks_cover_entire_text():
    text = "x" * 1000
    chunks = chunk_text(text, max_chunk_chars=100, overlap_chars=20)
    reconstructed = set()
    for chunk in chunks:
        for i in range(chunk.offset, chunk.offset + len(chunk.text)):
            reconstructed.add(i)
    assert reconstructed == set(range(1000))


def test_overlap_larger_than_chunk_is_clamped():
    text = "abcdef"
    # overlap >= max_chunk_chars would stall; ensure forward progress.
    chunks = chunk_text(text, max_chunk_chars=3, overlap_chars=10)
    assert chunks[0].offset == 0
    assert chunks[-1].text.endswith("f")
    # Must terminate with a finite number of chunks.
    assert len(chunks) < 10


def test_overlap_prevents_boundary_bypass():
    # A sensitive token spanning a boundary must be fully contained somewhere.
    text = "aaaaaSECRETbbbbb"
    chunks = chunk_text(text, max_chunk_chars=8, overlap_chars=6)
    assert any("SECRET" in c.text for c in chunks)


def test_zero_max_chunk_raises():
    with pytest.raises(ValueError):
        chunk_text("abc", 0, 0)
