#!/usr/bin/env python3
"""Module"""
from typing import Tuple, Union


def to_kv(k: str, v: Union[int, float]) -> tuple:
    """Function that that takes a string
    k and an int OR float v as arguments and returns a tuple"""
    x = Tuple[str, float]
    x = (k, v*v)
    return x
