from flask import Flask
from flask_password import PasswordHasher

class Config(object):
    PASSWORD_ALGORITHM = 'bcrypt'
    BCRYPT_ROUNDS = 14

app = Flask(__name__)
app.debug = True
app.config.from_object(Config())

pw = PasswordHasher()
pw.init_app(app)

hashed_password = pw.hash_password('my password')

print(hashed_password)
