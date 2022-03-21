#!/usr/bin/env python3
"""Insert a document in Python"""


def insert_school(mongo_collection, **kwargs):
    """"""
    result = mongo_collection.insert_one(kwargs)
    return result and result.inserted_id
