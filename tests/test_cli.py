import unittest

from cli import parse_context_argument


class CliTests(unittest.TestCase):
    def test_parse_context_argument_accepts_single_quoted_json(self):
        self.assertEqual(parse_context_argument('{"category": "schedule", "value": "tired"}'), {"category": "schedule", "value": "tired"})
        self.assertEqual(parse_context_argument("{'category': 'schedule', 'value': 'tired'}"), {"category": "schedule", "value": "tired"})


if __name__ == "__main__":
    unittest.main()
