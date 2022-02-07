#!/usr/bin/env python3
"""Simple helper function"""

from typing import Tuple


def index_range(page: int, page_size: int) -> Tuple[int, int]:
    """function that returns a tuple of size two
    containing a start index and an end index"""
    size = page * page_size
    return (size - page_size, size)
