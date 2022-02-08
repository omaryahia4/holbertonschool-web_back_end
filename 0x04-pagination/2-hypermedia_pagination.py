#!/usr/bin/env python3
"""Simple helper function"""

from typing import Dict, Tuple, List
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

    def get_hyper(self, page: int = 1, page_size: int = 10) -> Dict[str, str]:
        data = self.get_page(page, page_size)
        length = len(self.dataset())
        total_pages = math.ceil(length / page_size)
        page_s = len(self.get_page(page, page_size))
        if page > 1:
            prev_page = page - 1
        else:
            prev_page = None
        if page < length:
            next_page = page + 1
        else:
            next_page = None

        dic: Dict = {
            'page_size': page_s,
            'page': page,
            'data': data,
            'next_page': next_page,
            'prev_page': prev_page,
            'total_pages': total_pages
        }
        return dic
