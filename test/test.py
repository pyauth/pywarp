#!/usr/bin/env python

import os
import sys
import unittest
import tempfile
import json
import io
import platform

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from pywarp import RelyingPartyManager  # noqa

class TestPyWARP(unittest.TestCase):
    def test_pywarp(self):
        pass

if __name__ == '__main__':
    unittest.main()
