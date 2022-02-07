#!/usr/bin/env python3
"""Simple helper function"""

from typing import Tuple, List
import csv
import math


def index_range(page: int, page_size: int) -> Tuple[int, int]:
    """function that returns a tuple of size two
    containing a start index and an end index"""
    size = page * page_size
    return (size - page_size, size)


class Server:
    """Server class to paginate a database of popular baby names.
    """
    DATA_FILE = "Popular_Baby_Names.csv"

    def __init__(self):
        self.__dataset = None

    def dataset(self) -> List[List]:
        """Cached dataset
        """
        if self.__dataset is None:
            with open(self.DATA_FILE) as f:
                reader = csv.reader(f)
                dataset = [row for row in reader]
            self.__dataset = dataset[1:]

        return self.__dataset

    def get_page(self, page: int = 1, page_size: int = 10) -> List[List]:
        """get dataset
        """
        assert type(page) == int and page > 0
        assert type(page_size) == int and page_size > 0

        page, page_size = index_range(page, page_size)
        listt: List = []
        if page >= len(self.dataset()):
            return listt
        listt = self.dataset()
        return listt[page:page_size]
