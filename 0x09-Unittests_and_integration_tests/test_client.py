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

    @patch("client.get_json")
    def test_public_repos(self, get_patch):
        """"""
        get_patch.return_value = [{"name": "google"},
                                  {"name": "abc"}]
        with patch.object(GithubOrgClient, "_public_repos_url",
                          new_callable=PropertyMock) as mock_o:
            mock_o.return_value = "http://linkedin.com"
            github_client = GithubOrgClient("yahoo")
            response = github_client.public_repos()
            self.assertEqual(response, ["google", "abc"])
            get_patch.assert_called_once()
            mock_o.assert_called_once()

    @parameterized.expand([
        ({"license": {"key": "my_license"}}, "my_license", True),
        ({"license": {"key": "other_license"}}, "my_license", False)
    ])
    def test_has_license(self, repo, license, expected):
        """"""
        github_client = GithubOrgClient("yahoo")
        response = (github_client.has_license(repo, license))
        self.assertEqual(response, expected)


if __name__ == '__main__':
    unittest.main()
