from flask import Flask
from unittest import TestCase
from flask_password import PasswordHasher
from flask_password import PBKDF2PasswordHasher

class TestPBKDF2(TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config['PBKDF2_ITERATIONS'] = 30000
        self.pw = PBKDF2PasswordHasher()

    def test_is_string(self):
        hashed_password = self.pw.hash_password('password', self.pw.salt())
        self.assertTrue(isinstance(hashed_password, str))

    def test_not_string(self):
        pw_hash = self.pw.hash_password(42, self.pw.salt())
        self.assertTrue(isinstance(pw_hash, str))

    def test_algorithm(self):
        hashed_password = self.pw.hash_password('password', self.pw.salt())
        self.assertEqual('pbkdf2_sha256', PasswordHasher.get_algorithm(hashed_password))

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
        self.assertIn('$24000', hashed_password1)

    def test_different_hashes(self):
        salt1 = self.pw.salt()
        salt2 = self.pw.salt()

        hashed_password1 = self.pw.hash_password('password', salt1)
        hashed_password2 = self.pw.hash_password('password', salt2)
        self.assertNotEqual(hashed_password1, hashed_password2)
        self.assertIn(salt1, hashed_password1)
        self.assertIn(salt2, hashed_password2)

    def test_custom_iterations(self):
        hashed_password1 = self.pw.hash_password('password', self.pw.salt(), 1000)
        hashed_password2 = self.pw.hash_password('password', self.pw.salt(), 2000)
        self.assertIn('$1000', hashed_password1)
        self.assertIn('$2000', hashed_password2)

    def test_default_iterations(self):
        hashed_password1 = self.pw.hash_password('password', self.pw.salt())
        self.assertIn('$24000', hashed_password1)

        self.pw.init_app(self.app)

        hashed_password1 = self.pw.hash_password('password', self.pw.salt())
        self.assertIn('$30000', hashed_password1)

    def test_check_hash(self):
        hashed_password = self.pw.hash_password('password', self.pw.salt())

        self.assertTrue(self.pw.check_password('password', hashed_password))
        self.assertFalse(self.pw.check_password('wrong', hashed_password))
