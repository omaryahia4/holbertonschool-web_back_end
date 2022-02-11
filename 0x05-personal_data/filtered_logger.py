#!/usr/bin/env python3
"""log message"""
from typing import List
import re


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    for field in fields:
        message = re.sub(r'{}=.*?{}'.format(field, separator),
                         "{}={}{}".format(field,
                                          redaction, separator), message)
    return message
