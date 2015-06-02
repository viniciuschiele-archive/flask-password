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
from unittest import TestCase


class TestHasher(TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.pw = PasswordHasher(self.app)

    def test_default_algorithm(self):
        self.assertEqual(self.pw.algorithm, 'pbkdf2_sha256')

    def test_hash_password(self):
        hashed_password1 = self.pw.hash_password('password')
        hashed_password2 = self.pw.hash_password('password')
        self.assertNotEqual(hashed_password1, hashed_password2)

    def test_check_hash(self):
        hashed_password = self.pw.hash_password('password')

        self.assertTrue(self.pw.check_password('password', hashed_password))
        self.assertFalse(self.pw.check_password('wrong', hashed_password))
