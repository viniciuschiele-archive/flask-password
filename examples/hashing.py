from flask import Flask
from flask import request
from flask import render_template
from flask import Response
from flask_password import PasswordHasher

app = Flask(__name__)
app.debug = True

pw = PasswordHasher()
pw.init_app(app)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'GET':
        return Response(render_template('hashing.html'))

    password = request.form.get('password')
    algorithm = request.form.get('algorithm')
    hashed_password = pw.hash_password(password, algorithm=algorithm)

    return Response(render_template('hashing.html',
                                    hashed_password=hashed_password,
                                    hashed_password_length=len(hashed_password)))

if __name__ == '__main__':
    app.run()
