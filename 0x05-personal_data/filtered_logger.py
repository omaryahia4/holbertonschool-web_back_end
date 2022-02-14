#!/usr/bin/env python3
"""log message"""
from typing import List, Tuple
import re
import logging

PII_FIELDS: Tuple[str, str, str, str, str]\
    = ("email", "phone", "ssn", "password", 'ip')


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """Constructor"""
        self.fields = fields
        super(RedactingFormatter, self).__init__(self.FORMAT)

    def format(self, record: logging.LogRecord) -> str:
        """ method that filters values in incoming
        log records using filter_datum function"""
        return filter_datum(self.fields, self.REDACTION,
                            super().format(record), self.SEPARATOR)


def get_logger() -> logging.Logger:
    """function that takes no arguments
    and returns a logging.Logger object."""
    logging.basicConfig()
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.addHandler(logging.StreamHandler()
                      .setFormatter(RedactingFormatter(PII_FIELDS)))
    return logger


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    """function called filter_datum that
    returns the log message obfuscated"""
    for field in fields:
        message = re.sub(r'{}=.*?{}'.format(field, separator),
                         "{}={}{}".format(field,
                                          redaction, separator), message)
    return message
