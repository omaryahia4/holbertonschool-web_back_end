#!/usr/bin/env python3
"""test client"""
import unittest
from client import GithubOrgClient
from parameterized import parameterized
from unittest.mock import patch


class TestGithubOrgClient(unittest.TestCase):
    """"""
    @parameterized.expand([
        ["google"],
        ["abc"],
    ])
    @patch("client.get_json")
    def test_org(self, url, payload):
        """ Method that tests GithubOrgClient """
        test_class = GithubOrgClient(url)
        self.assertEqual(test_class.org, payload.return_value)
        payload.assert_called_once()


if __name__ == '__main__':
    unittest.main()
