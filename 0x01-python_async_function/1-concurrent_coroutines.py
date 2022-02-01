#!/usr/bin/env python3
"""multiple coroutines"""

import typing


wait_random = __import__('0-basic_async_syntax').wait_random


async def wait_n(n: int, max_delay: int) -> typing.List[float]:
    l: typing.List[float] = []
    for _ in range(n):
        task = await wait_random(max_delay)
        l.append(task)
    return sorted(l)
