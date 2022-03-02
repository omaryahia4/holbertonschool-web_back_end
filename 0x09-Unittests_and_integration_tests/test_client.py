#!/usr/bin/env python3
"""test client"""
import unittest
from client import GithubOrgClient
from parameterized import parameterized
from unittest.mock import PropertyMock, patch


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

    def test_public_repos_url(self):
        """Test that the result of _public_repos_url
        is the expected one based on the mocked payload."""
        with patch.object(GithubOrgClient,
                          "org",
                          new_callable=PropertyMock) as patched:
            test_json = {"url": "linkedin",
                         "repos_url": "http://google.com"}
            patched.return_value = test_json
            github_client = GithubOrgClient(test_json.get("url"))
            response = github_client._public_repos_url
            patched.assert_called_once()
            self.assertEqual(response, test_json.get("repos_url"))


if __name__ == '__main__':
    unittest.main()
