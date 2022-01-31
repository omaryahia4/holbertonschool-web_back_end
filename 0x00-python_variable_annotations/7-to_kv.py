#!/usr/bin/env python3
"""Module"""
from typing import Tuple, Union


def to_kv(k: str, v: Union[int, float]) -> Tuple[str, float]:
    """Function that that takes a string
    k and an int OR float v as arguments and returns a tuple"""
    return (k, v*v)
