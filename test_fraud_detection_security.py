"""
Security tests for fraud_detection.py focusing on hardcoded password remediation.

This test suite validates that:
1. The PASSWORD_CANARY environment variable is properly required
2. The application fails securely when PASSWORD_CANARY is not set
3. The application initializes correctly when PASSWORD_CANARY is properly configured
4. No hardcoded passwords remain in the password_canary variable
"""

import unittest
import os
import sys
from unittest.mock import patch, MagicMock
import importlib


class TestPasswordCanarySecurityRemediation(unittest.TestCase):
    """Test cases for PASSWORD_CANARY hardcoded password remediation"""

    def setUp(self):
        """Set up test fixtures"""
        # Remove fraud_detection from sys.modules if it exists to force reimport
        if 'fraud_detection' in sys.modules:
            del sys.modules['fraud_detection']

        # Clean up any PASSWORD_CANARY from environment
        if 'PASSWORD_CANARY' in os.environ:
            del os.environ['PASSWORD_CANARY']

    def tearDown(self):
        """Clean up after tests"""
        # Remove fraud_detection from sys.modules
        if 'fraud_detection' in sys.modules:
            del sys.modules['fraud_detection']

        # Clean up environment variable
        if 'PASSWORD_CANARY' in os.environ:
            del os.environ['PASSWORD_CANARY']

    @patch('fraud_detection.FraudService')
    @patch('fraud_detection.FraudModel')
    def test_password_canary_missing_raises_error(self, mock_model, mock_service):
        """Test that missing PASSWORD_CANARY environment variable raises ValueError"""
        # Ensure PASSWORD_CANARY is not set
        if 'PASSWORD_CANARY' in os.environ:
            del os.environ['PASSWORD_CANARY']

        # Attempt to import should raise ValueError
        with self.assertRaises(ValueError) as context:
            import fraud_detection

        # Verify the error message is appropriate
        self.assertIn("PASSWORD_CANARY", str(context.exception))
        self.assertIn("environment variable", str(context.exception).lower())

    @patch('fraud_detection.FraudService')
    @patch('fraud_detection.FraudModel')
    def test_password_canary_empty_string_raises_error(self, mock_model, mock_service):
        """Test that empty PASSWORD_CANARY environment variable raises ValueError"""
        # Set PASSWORD_CANARY to empty string
        os.environ['PASSWORD_CANARY'] = ''

        # Empty string evaluates to False/None, should raise ValueError
        with self.assertRaises(ValueError) as context:
            import fraud_detection

        self.assertIn("PASSWORD_CANARY", str(context.exception))

    @patch('fraud_detection.FraudService')
    @patch('fraud_detection.FraudModel')
    def test_password_canary_valid_environment_variable(self, mock_model, mock_service):
        """Test that valid PASSWORD_CANARY environment variable is loaded correctly"""
        # Set a valid PASSWORD_CANARY
        test_password = "test_secure_P@ssw0rd_123"
        os.environ['PASSWORD_CANARY'] = test_password

        # Import should succeed
        import fraud_detection

        # Verify password_canary is set from environment
        self.assertEqual(fraud_detection.password_canary, test_password)
        self.assertIsNotNone(fraud_detection.password_canary)

    @patch('fraud_detection.FraudService')
    @patch('fraud_detection.FraudModel')
    def test_password_canary_not_hardcoded(self, mock_model, mock_service):
        """Test that password_canary is NOT set to the old hardcoded value"""
        # Set a different password
        test_password = "different_secure_password"
        os.environ['PASSWORD_CANARY'] = test_password

        import fraud_detection

        # Verify the old hardcoded password is NOT present
        hardcoded_value = "my1obvious_P@ssword3"
        self.assertNotEqual(fraud_detection.password_canary, hardcoded_value)

        # Verify it uses the environment variable
        self.assertEqual(fraud_detection.password_canary, test_password)

    @patch('fraud_detection.FraudService')
    @patch('fraud_detection.FraudModel')
    def test_password_canary_accepts_complex_passwords(self, mock_model, mock_service):
        """Test that PASSWORD_CANARY accepts complex password formats"""
        complex_passwords = [
            "C0mpl3x!P@ssw0rd#2024",
            "Very$ecure&Pass*123",
            "MultiPart-Password_With.Special/Chars",
            "!@#$%^&*()_+-=[]{}|;':,.<>?",
            "Unicode_パスワード_123"
        ]

        for test_password in complex_passwords:
            # Clean up
            if 'fraud_detection' in sys.modules:
                del sys.modules['fraud_detection']

            os.environ['PASSWORD_CANARY'] = test_password

            import fraud_detection

            self.assertEqual(fraud_detection.password_canary, test_password,
                           f"Failed to properly load password: {test_password}")

    @patch('fraud_detection.FraudService')
    @patch('fraud_detection.FraudModel')
    def test_password_canary_no_default_fallback(self, mock_model, mock_service):
        """Test that there is no insecure default fallback when PASSWORD_CANARY is missing"""
        # Ensure PASSWORD_CANARY is not set
        if 'PASSWORD_CANARY' in os.environ:
            del os.environ['PASSWORD_CANARY']

        # Should raise ValueError, not provide a default
        with self.assertRaises(ValueError):
            import fraud_detection

    @patch('fraud_detection.FraudService')
    @patch('fraud_detection.FraudModel')
    def test_password_canary_security_best_practice(self, mock_model, mock_service):
        """Test that the implementation follows security best practices"""
        # Set valid password
        os.environ['PASSWORD_CANARY'] = "secure_test_password"

        import fraud_detection

        # Verify password_canary is a string (not None, not empty)
        self.assertIsInstance(fraud_detection.password_canary, str)
        self.assertTrue(len(fraud_detection.password_canary) > 0)

        # Verify it came from environment, not hardcoded
        self.assertEqual(fraud_detection.password_canary,
                        os.environ['PASSWORD_CANARY'])

    @patch('fraud_detection.FraudService')
    @patch('fraud_detection.FraudModel')
    def test_application_fails_fast_without_password_canary(self, mock_model, mock_service):
        """Test that the application fails fast at startup without PASSWORD_CANARY"""
        # This is a security best practice - fail fast and loud
        if 'PASSWORD_CANARY' in os.environ:
            del os.environ['PASSWORD_CANARY']

        with self.assertRaises(ValueError) as context:
            import fraud_detection

        # Ensure the error is raised during module initialization
        error_msg = str(context.exception)
        self.assertTrue(len(error_msg) > 0)
        self.assertIn("PASSWORD_CANARY", error_msg)

    @patch('fraud_detection.FraudService')
    @patch('fraud_detection.FraudModel')
    def test_password_canary_whitespace_only_invalid(self, mock_model, mock_service):
        """Test that whitespace-only PASSWORD_CANARY is treated as invalid"""
        whitespace_values = ['   ', '\t', '\n', '\r\n', '  \t\n  ']

        for whitespace in whitespace_values:
            # Clean up
            if 'fraud_detection' in sys.modules:
                del sys.modules['fraud_detection']

            os.environ['PASSWORD_CANARY'] = whitespace

            # Whitespace should be treated as invalid (empty after strip)
            with self.assertRaises(ValueError):
                import fraud_detection

    @patch('fraud_detection.FraudService')
    @patch('fraud_detection.FraudModel')
    def test_password_canary_source_code_check(self, mock_model, mock_service):
        """Verify the hardcoded password 'my1obvious_P@ssword3' is removed from source"""
        # Read the source file
        with open('fraud_detection.py', 'r') as f:
            source_code = f.read()

        # Verify the hardcoded password is NOT in the source code
        hardcoded_password = "my1obvious_P@ssword3"
        self.assertNotIn(hardcoded_password, source_code,
                        "Hardcoded password 'my1obvious_P@ssword3' still found in source code!")

        # Verify environment variable approach is used
        self.assertIn("os.getenv", source_code,
                     "Environment variable approach not found in source code")
        self.assertIn("PASSWORD_CANARY", source_code,
                     "PASSWORD_CANARY not referenced in source code")


class TestPasswordCanaryRegressionPrevention(unittest.TestCase):
    """Regression tests to prevent reintroduction of hardcoded passwords"""

    def test_no_hardcoded_passwords_in_source(self):
        """Verify no obvious hardcoded passwords exist in fraud_detection.py"""
        with open('fraud_detection.py', 'r') as f:
            source_code = f.read()

        # List of known hardcoded passwords that should NOT be present
        forbidden_passwords = [
            "my1obvious_P@ssword3",
            '"my1obvious_P@ssword3"',
            "'my1obvious_P@ssword3'"
        ]

        for forbidden_password in forbidden_passwords:
            self.assertNotIn(forbidden_password, source_code,
                           f"Hardcoded password '{forbidden_password}' found in source code!")

    def test_password_canary_uses_environment_variable(self):
        """Verify password_canary assignment uses os.getenv"""
        with open('fraud_detection.py', 'r') as f:
            source_code = f.read()

        # Check for environment variable usage pattern
        self.assertIn('password_canary', source_code)
        self.assertIn('os.getenv', source_code)

        # Verify it's used for password_canary (case-insensitive search nearby)
        lines = source_code.split('\n')
        found_secure_pattern = False
        for i, line in enumerate(lines):
            if 'password_canary' in line.lower():
                # Check surrounding lines for os.getenv
                context = '\n'.join(lines[max(0, i-2):min(len(lines), i+3)])
                if 'os.getenv' in context and 'PASSWORD_CANARY' in context:
                    found_secure_pattern = True
                    break

        self.assertTrue(found_secure_pattern,
                       "password_canary does not use os.getenv with PASSWORD_CANARY")


if __name__ == '__main__':
    unittest.main()
