#!/usr/bin/env python3
""""""


import typing
from typing import Tuple

x = Tuple[str, float]
def to_kv(k: str, v: typing.Union[int, float])-> tuple:
    x = (k, v*v)
    return x