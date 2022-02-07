#!/usr/bin/env python3
"""Simple helper function"""

from typing import Tuple


def index_range(page: int, page_size: int) -> Tuple[int, int]:
    """function that returns a tuple of size two
    containing a start index and an end index"""
    count = 0
    page_content = page_size
    li = []
    for i in range(page, page_size):
        if i > 11:
            count += 10
    page_content += count
    li.extend([count, page_content])
    return tuple(li)
