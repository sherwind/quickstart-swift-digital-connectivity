"""Testing for Secrets that emit by the stacks"""
from tests.parent_testcase import ParentTestCase


class TestSecretsManager(ParentTestCase):
    """Testing for Secrets that emit by the stacks"""

    def test_secrets_exists(self):
        """should have secrets created """
        result = self.sec_man_client.list_secrets()
        self.assertEqual(len(result["SecretList"]), 1)
