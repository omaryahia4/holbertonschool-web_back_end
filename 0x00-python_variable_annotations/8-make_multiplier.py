#!/usr/bin/env python3
""""""


import typing


def make_multiplier(multiplier: float) -> typing.Callable[[float], float]:
    """Function that takes a float multiplier as argument and
    returns a function that multiplies a float by multiplier."""
    def mult(x: float):
        return x * multiplier
    return mult
