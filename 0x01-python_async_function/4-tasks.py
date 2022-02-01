#!/usr/bin/env python3
"""Execution time"""

import typing


task_wait_random = __import__('3-tasks').task_wait_random


async def task_wait_n(n: int, max_delay: int = 10) -> typing.List[float]:
    """Function that returns list of function's delays"""
    l: typing.List[float] = []
    for _ in range(n):
        task = await task_wait_random(max_delay)
        l.append(task)
    return sorted(l)
