from flask import Flask, render_template, redirect, request, session
from werkzeug.utils import secure_filename
import sqlite3
from sqlite3 import Error
from flask_bcrypt import Bcrypt
import os

# define some important stuff
DATABASE = "maoridictionary.db"
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "ueuywq9571"

MIN_PASSWORD_LENGTH = 8
PASSWORD_REGEX_REQUIREMENTS = "^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9]).*$"
USER_NAME_REGEX_REQUIREMENTS = "^[a-zA-Z0-9]+$"


def is_logged_in_as_teacher():
    if session.get("email") is None:
        print("not logged in")
        return [False, False]
    else:
        if session.get("user_type") == 2:
            print("logged in")
            # logged in is true, and as teacher is true
            return [True, True]
        elif session.get("user_type") == 1 :
            # logged in is true, but as teacher is false
            return [True, False]

def open_database(db_name):
    try:
        connection = sqlite3.connect(db_name)
        return connection
    except Error as e:
        print(e)
    return None

@app.route('/')
def render_home():  # put application's code here
    return render_template('home.html', logged_in=is_logged_in_as_teacher())

@app.route('/categories/words-category')
def render_words_list():
    if not is_logged_in_as_teacher()[0]:
        return redirect('/?message=need+to+be+logged+in')
    return render_template('words-category.html', logged_in=is_logged_in_as_teacher())


@app.route('/signup', methods=['POST', 'GET'])
def render_signup():
    if is_logged_in_as_teacher()[0]:
        return redirect('/?message=already+logged+in')
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

        con = open_database(DATABASE)
        query = "INSERT INTO users (name, email, password, user_type) VALUES (?, ?, ?, ?)"
        cur = con.cursor()

        try:
            cur.execute(query, (user_name, email, hashed_password, user_type))
        except sqlite3.IntegrityError:
            con.close()
            return redirect('/signup?error=Email+is+already+used')
        con.commit()
        con.close()

        return redirect('/login')

    return render_template('signup.html', min_password=MIN_PASSWORD_LENGTH, password_regex=PASSWORD_REGEX_REQUIREMENTS, user_name_regex=USER_NAME_REGEX_REQUIREMENTS, logged_in=is_logged_in_as_teacher())

@app.route('/login', methods=["POST", "GET"])
def render_login():
    if is_logged_in_as_teacher()[0]:
        return redirect('/?message=already+logged+in')
    if request.method == 'POST':
        email = request.form['email_address'].strip().lower()
        password = request.form['password'].strip()
        query = "SELECT id, name, password, user_type  FROM users WHERE email = ?"
        con = open_database(DATABASE)
        cur = con.cursor()
        cur.execute(query, (email,))
        user_data = cur.fetchall()
        con.close()
        print(user_data)

        if user_data is None:
            return redirect('/login?error=Email+invalid')
        try:
            user_id = user_data[0][0]
            user_name = user_data[0][1]
            db_password = user_data[0][2]
            user_type = user_data[0][3]
        except IndexError:
            return redirect('/login?error=Email+invalid+or+password+incorrect')

        if not bcrypt.check_password_hash(db_password, password):
            return redirect(request.referrer + "?error=Password+incorrect")

        session['email'] = email
        session['user_id'] = user_id
        session["name"] = user_name
        session["user_type"] = user_type

        print(session)

        return redirect('/')


    return render_template('login.html', logged_in=is_logged_in_as_teacher())

@app.route('/logout')
def logout():
    print(list(session.keys()))
    [session.pop(key) for key in list(session.keys())]
    print(list(session.keys()))
    return redirect('/?message=See+you+nest+time!')

@app.route('/admin')
def admin():
    if not is_logged_in_as_teacher()[1]:
        return redirect('/?message=Need+to+be+logged+in+as+teacher')

    return render_template('admin.html', logged_in=is_logged_in_as_teacher())

@app.route('/categories/words-category/word')
def render_word():
    if not is_logged_in_as_teacher()[0]:
        return redirect('/?message=Need+to+be+logged+in')
    return render_template('word.html', logged_in=is_logged_in_as_teacher())

@app.errorhandler(404)
def page_not_found(e):
    print(e)
    return render_template('404Error.html', logged_in=is_logged_in_as_teacher()), 404

if __name__ == '__main__':
    app.run()
