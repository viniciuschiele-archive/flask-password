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

import base64
import hashlib
import os

from abc import ABCMeta
from abc import abstractmethod
from .utils import import_string


try:
    import bcrypt
except ImportError:
    bcrypt = None


class PasswordHasher(object):
    PASSWORD_HASHERS = [
        'flask_password.hashers.BCryptPasswordHasher',
        'flask_password.hashers.MD5PasswordHasher',
        'flask_password.hashers.PBKDF2PasswordHasher'
    ]

    def __init__(self, app=None):
        self.__algorithm = None
        self.__hashers = {}

        if app:
            self.init_app(app)

    def init_app(self, app):
        self.__algorithm = app.config.get('PASSWORD_ALGORITHM')

        classes = app.config.get('PASSWORD_HASHERS', self.PASSWORD_HASHERS)

        for class_name in classes:
            hasher_cls = import_string(class_name)
            hasher = hasher_cls()
            hasher.init_app(app)
            self.__hashers[hasher.algorithm] = hasher

            if not self.__algorithm:
                self.__algorithm = hasher.algorithm

    def check_password(self, password, hashed_password):
        algorithm = self.get_algorithm(hashed_password)
        hasher = self.get_hasher(algorithm)
        return hasher.check_password(password, hashed_password)

    def hash_password(self, password, salt=None, algorithm=None):
        if not algorithm:
            algorithm = self.__algorithm

        hasher = self.__hashers.get(algorithm)

        if not salt:
            salt = hasher.salt()

        return hasher.hash_password(password, salt)

    @staticmethod
    def get_algorithm(hashed_password):
        return hashed_password.split('$', 1)[0]

    def get_hasher(self, algorithm):
        try:
            return self.__hashers[algorithm]
        except KeyError:
            raise ValueError("Unknown password hashing algorithm '%s'. " % algorithm)


class BasePasswordHasher(metaclass=ABCMeta):
    def init_app(self, app):
        pass

    @abstractmethod
    def check_password(self, password, hashed_password):
        pass

    @abstractmethod
    def hash_password(self, password, salt):
        pass

    def salt(self):
        return base64.b64encode(os.urandom(16)).decode()


class BCryptPasswordHasher(BasePasswordHasher):
    algorithm = 'bcrypt'
    rounds = 12

    def init_app(self, app):
        rounds = app.config.get('BCRYPT_ROUNDS')
        if rounds:
            self.rounds = rounds

    def check_password(self, password, hashed_password):
        self.__check_bcrypt()

        algorithm, data = hashed_password.split('$', 1)

        password = password.encode()
        hashed_password = data.encode()

        return bcrypt.checkpw(password, hashed_password)

    def hash_password(self, password, salt):
        self.__check_bcrypt()

        password = password.encode()

        data = bcrypt.hashpw(password, salt)
        return "%s$%s" % (self.algorithm, data)

    def salt(self, rounds=None):
        self.__check_bcrypt()

        if not rounds:
            rounds = self.rounds
        return bcrypt.gensalt(rounds)

    @staticmethod
    def __check_bcrypt():
        if not bcrypt:
            raise ImportError('bcrypt library is not installed. (pip install py-bcrypt)')


class PBKDF2PasswordHasher(BasePasswordHasher):
    algorithm = "pbkdf2_sha256"
    iterations = 24000
    digest = hashlib.sha256

    def init_app(self, app):
        iterations = app.config.get('PBKDF2_ITERATIONS')
        if iterations:
            self.iterations = iterations

    def check_password(self, password, hashed_password):
        algorithm, iterations, salt, hash = hashed_password.split('$', 3)
        return self.hash_password(password, salt, int(iterations)) == hashed_password

    def hash_password(self, password, salt, iterations=None):
        if not iterations:
            iterations = self.iterations

        password_bytes = password.encode()
        salt_bytes = salt.encode()

        hash = hashlib.pbkdf2_hmac(self.digest().name, password_bytes, salt_bytes, iterations)
        hash = base64.b64encode(hash).decode('ascii').strip()
        return "%s$%s$%s$%s" % (self.algorithm, iterations, salt, hash)


class MD5PasswordHasher(BasePasswordHasher):
    algorithm = "md5"

    def check_password(self, password, hashed_password):
        algorithm, salt, hash = hashed_password.split('$', 2)
        return self.hash_password(password, salt) == hashed_password

    def hash_password(self, password, salt):
        hash = hashlib.md5((salt + password).encode()).hexdigest()
        return "%s$%s$%s" % (self.algorithm, salt, hash)


class SHA1PasswordHasher(BasePasswordHasher):
    algorithm = "sha1"

    def check_password(self, password, hashed_password):
        algorithm, salt, hash = hashed_password.split('$', 2)
        return self.hash_password(password, salt) == hashed_password

    def hash_password(self, password, salt):
        hash = hashlib.sha1((salt + password).encode()).hexdigest()
        return "%s$%s$%s" % (self.algorithm, salt, hash)
