"""Binary input opening and bounded physical-line iteration."""

from __future__ import annotations

import gzip
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO

from .models import InputLine

DEFAULT_MAX_LINE_LENGTH = 64 * 1024


@contextmanager
def open_binary_input(path: Path) -> Iterator[BinaryIO]:
    """Open a plain or ``.gz`` input as a binary stream."""
    if path.suffix.lower() == ".gz":
        stream = gzip.open(path, "rb")
    else:
        stream = path.open("rb")
    try:
        yield stream
    finally:
        stream.close()


def iter_bounded_lines(
    stream: BinaryIO, max_line_length: int = DEFAULT_MAX_LINE_LENGTH
) -> Iterator[InputLine]:
    """Yield decoded physical lines without retaining an oversized line.

    The limit applies to logical content after a trailing LF or CRLF is
    removed. Oversized input is drained in bounded chunks before iteration
    resumes, preserving physical-line synchronization.
    """
    if max_line_length < 1:
        raise ValueError("max_line_length must be positive")

    line_number = 0
    read_size = max_line_length + 2  # permits max bytes plus CRLF
    while True:
        chunk = stream.readline(read_size)
        if not chunk:
            return
        line_number += 1

        terminated = chunk.endswith(b"\n")
        content = chunk[:-1] if terminated else chunk
        if content.endswith(b"\r"):
            content = content[:-1]

        if len(content) > max_line_length or (
            not terminated and len(chunk) == read_size
        ):
            while not chunk.endswith(b"\n"):
                chunk = stream.readline(read_size)
                if not chunk:
                    break
            yield InputLine(line_number, "", "line_too_long")
            continue

        try:
            text = content.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            # Replacement gives reporting code a safe, bounded preview while
            # keeping invalid encoding distinct from outer-format failures.
            text = content.decode("utf-8", errors="replace")
            yield InputLine(line_number, text, "invalid_encoding")
            continue
        yield InputLine(line_number, text)
