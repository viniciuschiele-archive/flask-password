import base64
import hashlib
import os

from abc import ABCMeta
from abc import abstractmethod
from .utils import force_bytes
from .utils import force_text
from .utils import import_string


try:
    import bcrypt
except ImportError:
    bcrypt = None


class PasswordHasher(object):
    PASSWORD_HASHERS = [
        'flask_password.hashers.BCryptPasswordHasher',
        'flask_password.hashers.PBKDF2PasswordHasher'
    ]

    def __init__(self, app=None):
        self.__default_algorithm = None
        self.__hashers = {}

        if app:
            self.init_app(app)

    def init_app(self, app):
        self.__default_algorithm = app.config.get('DEFAULT_ALGORITHM')

        classes = app.config.get('PASSWORD_HASHERS', self.PASSWORD_HASHERS)

        for class_name in classes:
            hasher_cls = import_string(class_name)
            hasher = hasher_cls()
            hasher.init_app(app)
            self.__hashers[hasher.algorithm] = hasher

            if not self.__default_algorithm:
                self.__default_algorithm = hasher.algorithm

    def check_password(self, password, hashed_password):
        algorithm = self.get_algorithm(hashed_password)
        hasher = self.get_algorithm(algorithm)
        return hasher.check_password(password, hashed_password)

    def hash_password(self, password, salt=None, algorithm=None):
        if not algorithm:
            algorithm = self.__default_algorithm

        hasher = self.__hashers.get(algorithm)

        if not salt:
            salt = hasher.salt()

        return hasher.hash_password(password, salt)

    def get_hasher(self, algorithm):
        try:
            return self.__hashers[algorithm]
        except KeyError:
            raise ValueError("Unknown password hashing algorithm '%s'. " % algorithm)

    @staticmethod
    def get_algorithm(hashed_password):
        return hashed_password.split('$', 1)[0]


class BasePasswordHasher(metaclass=ABCMeta):
    @abstractmethod
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
        self.__validate_library()

        algorithm, data = hashed_password.split('$', 1)

        password = force_bytes(password)
        hashed_password = force_bytes(data)

        return bcrypt.checkpw(password, hashed_password)

    def hash_password(self, password, salt):
        self.__validate_library()

        password = force_bytes(password)

        data = bcrypt.hashpw(password, salt)
        return "%s$%s" % (self.algorithm, force_text(data))

    def salt(self, rounds=None):
        self.__validate_library()

        if not rounds:
            rounds = self.rounds
        return bcrypt.gensalt(rounds)

    @staticmethod
    def __validate_library():
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

        password_bytes = force_bytes(password)
        salt_bytes = force_bytes(salt)

        hash = hashlib.pbkdf2_hmac(self.digest().name, password_bytes, salt_bytes, iterations)
        hash = base64.b64encode(hash).decode('ascii').strip()
        return "%s$%s$%s$%s" % (self.algorithm, iterations, salt, hash)
