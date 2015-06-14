from flask import Flask
from flask_password import PasswordHasher


class Config(object):
    PASSWORD_ALGORITHM = 'pbkdf2'
    PBKDF2_ITERATIONS = 50000

app = Flask(__name__)
app.debug = True
app.config.from_object(Config())

pw = PasswordHasher()
pw.init_app(app)

hashed_password = pw.hash_password('my password')

print(hashed_password)
