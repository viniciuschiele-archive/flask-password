# Copyright 2015 Vinicius Chiele. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from flask import Flask
from flask_password import PasswordHasher
from flask_password.hashers import SHA1PasswordHasher
from unittest import TestCase


class TestSHA1(TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.pw = SHA1PasswordHasher()

    def test_algorithm(self):
        hashed_password = self.pw.hash_password('password', self.pw.salt())
        self.assertEqual(SHA1PasswordHasher.algorithm, PasswordHasher.get_algorithm(hashed_password))

    def test_salt(self):
        self.assertNotEqual(self.pw.salt(), None)
        self.assertNotEqual(self.pw.salt(), '')
        self.assertIsInstance(self.pw.salt(), str)
        self.assertNotEqual(self.pw.salt(), self.pw.salt())

    def test_equal_hashes(self):
        salt = self.pw.salt()
        hashed_password1 = self.pw.hash_password('password', salt)
        hashed_password2 = self.pw.hash_password('password', salt)
        self.assertEqual(hashed_password1, hashed_password2)
        self.assertIn(salt, hashed_password1)

    def test_different_hashes(self):
        salt1 = self.pw.salt()
        salt2 = self.pw.salt()

        hashed_password1 = self.pw.hash_password('password', salt1)
        hashed_password2 = self.pw.hash_password('password', salt2)
        self.assertNotEqual(hashed_password1, hashed_password2)
        self.assertIn(salt1, hashed_password1)
        self.assertIn(salt2, hashed_password2)

    def test_check_hash(self):
        hashed_password = self.pw.hash_password('password', self.pw.salt())

        self.assertTrue(self.pw.check_password('password', hashed_password))
        self.assertFalse(self.pw.check_password('wrong', hashed_password))
