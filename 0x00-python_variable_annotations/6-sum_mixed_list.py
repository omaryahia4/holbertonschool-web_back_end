#!/usr/bin/env python3
""""""
import typing


def sum_mixed_list(mxd_lst: typing.List[typing.Union[int, float]]) -> float:
    """Function that takes a list of integers and floats
    and returns their sum as a float."""
    return sum(mxd_lst)
