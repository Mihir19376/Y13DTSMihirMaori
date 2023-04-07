from flask import Flask, render_template, redirect, request, session
from werkzeug.utils import secure_filename
import sqlite3
from sqlite3 import Error
from flask_bcrypt import Bcrypt
import os

# define some important stuff
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "ueuywq9571"

MIN_PASSWORD_LENGTH = 8
PASSWORD_REGEX_REQUIREMENTS = "^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9]).*$"
USER_NAME_REGEX_REQUIREMENTS = "^[a-zA-Z0-9]+$"

@app.route('/')
def render_home():  # put application's code here
    return render_template('home.html')

@app.route('/categories/words-category')
def render_words_list():
    return render_template('words-category.html')


@app.route('/signup', methods=['POST', 'GET'])
def render_signup():
    if request.method == 'POST':
        print(request.form)
        user_name = request.form.get('user_name').strip()
        email = request.form.get('email_address').strip()
        user_type = request.form['qualification']
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        if password1 != password2:
            return redirect('\signup?error=passwords+do+not+match')

        hashed_password = bcrypt.generate_password_hash(password1)
        print(user_name, email, password1, user_type, hashed_password)

    return render_template('signup.html', min_password=MIN_PASSWORD_LENGTH, password_regex=PASSWORD_REGEX_REQUIREMENTS, user_name_regex=USER_NAME_REGEX_REQUIREMENTS)

@app.route('/login')
def render_login():
    return render_template('login.html')

@app.route('/categories/words-category/word')
def render_word():
    return render_template('word.html')

@app.errorhandler(404)
def page_not_found(e):
    print(e)
    return render_template('404Error.html'), 404

if __name__ == '__main__':
    app.run()
