from flask import Flask, render_template, redirect, request, session, flash
from werkzeug.utils import secure_filename
import sqlite3
from sqlite3 import Error
from flask_bcrypt import Bcrypt
import os
from datetime import datetime

# define some important stuff
DATABASE = "maoridictionary.db"
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "ueuywq9571"
upload = 'static/images'
app.config['UPLOAD'] = upload

MIN_PASSWORD_LENGTH = 8
PASSWORD_REGEX_REQUIREMENTS = "^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9]).*$"
# USER_NAME_REGEX_REQUIREMENTS = "^[a-zA-Z0-9]+$"
USER_NAME_REGEX_REQUIREMENTS = "^[\w'\-,.][^0-9_!¡?÷?¿/\\+=@#$%ˆ&*(){}|~<>;:[\]]{2,}$"
LEVELS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
TEACHER_USER_TYPE = 2
STUDENT_USER_TYPE = 1


def redirect_and_flash(redirect_url, flash_message):
    flash(flash_message)
    return redirect(redirect_url)

def get_all_categories():
    query = "SELECT id, category FROM categories"
    con = open_database(DATABASE)
    cur = con.cursor()
    cur.execute(query)
    category_list = cur.fetchall()
    # category_list = [category[0] for category in category_list]
    con.close()
    return category_list


def check_log_in_status():
    if session.get("email") is None:
        print("not logged in")
        return [False, False]
    else:
        print('Logged In')
        return [True, session.get("user_type") == TEACHER_USER_TYPE]
        # if session.get("user_type") == TEACHER_USER_TYPE:
        #     print("logged in")
        #     # logged in is true, and as teacher is true
        #     return [True, True]
        # elif session.get("user_type") == STUDENT_USER_TYPE:
        #     # logged in is true, but as teacher is false
        #     return [True, False]


def open_database(db_name):
    try:
        connection = sqlite3.connect(db_name)
        return connection
    except Error as e:
        print(e)
    return None


def db_fetch_or_commit(query_string, query_parameters, push):
    con = open_database(DATABASE)
    cur = con.cursor()
    if not query_parameters:
        cur.execute(query_string)
    else:
        cur.execute(query_string, (query_parameters))

    if not push:
        data = cur.fetchall()
        con.close()
        return data
    else:
        con.commit()
        con.close()


@app.route('/delete-word', methods=['POST', 'GET'])
def delete_word():
    if not check_log_in_status()[1]:
        redirect_and_flash('/', 'Need to be logged in as teacher!')
    if request.method == 'POST':
        print(request.form)
        id = request.form.get('deletion_id')
        query = "DELETE FROM words WHERE id = ?"
        db_fetch_or_commit(query, (id,), True)
        flash("Word Deleted")
        return redirect('/')
    elif request.method == 'GET':
        return redirect_and_flash('/', 'Cant enter URL manually!')


@app.route('/edit-word', methods=['POST', 'GET'])
def edit_word():
    if not check_log_in_status()[1]:
        return redirect_and_flash('/', "Need to be logged in as teacher!")

    if request.method == 'POST':
        print(request.form)
        old_image = request.form.get('previous_img_src')
        word_id = request.form.get('id')
        maori_word = request.form.get('maori_word')  #
        english_word = request.form.get('english_word')  #
        definition = request.form.get('definition')  #
        year_level = request.form.get('level_id')  #
        category = request.form.get('cat_id')
        author = session.get("user_id")  #
        time_of_entry = datetime.now()  #
        file = request.files['image_file']
        image_src = secure_filename(file.filename)  #

        query = f"SELECT * FROM words WHERE maori_name = ? AND english_name = ? AND NOT id = ?"
        word_already_exits = bool(db_fetch_or_commit(query, (maori_word, english_word, word_id), False))

        if not word_already_exits:
            query = "UPDATE words SET maori_name = ?, english_name = ?, definition = ?, last_edit_time = ?, author_of_entry = ?, year_level = ?, category = ? WHERE id = ?"
            db_fetch_or_commit(query, (maori_word, english_word, definition, time_of_entry, author, year_level, category, word_id,), True)

            if image_src == "":
                return redirect_and_flash(f'/words/{word_id}', 'Updated!')
            else:
                print(image_src)
                file.save(os.path.join(app.config['UPLOAD'], image_src))
                query = "UPDATE words SET img_src = ? WHERE id = ?"
                db_fetch_or_commit(query, (image_src, word_id,), True)
                if old_image != "no-image-available.png" and old_image != '':
                    os.remove(f'static/images/{old_image}')
                return redirect_and_flash(f'/words/{word_id}', 'Updated!')
        else:
            return redirect_and_flash('/', 'This word with the same meaning already exits!')
    elif request.method == 'GET':
        return redirect_and_flash('/', 'Cant enter URL manually!')


@app.route('/')
def render_home():  # put application's code here
    return render_template('home.html', logged_in=check_log_in_status(), category_list=get_all_categories())


@app.route("/search", methods=["GET", "POST"])
def render_search():
    if request.method == 'POST':
        print(request.form)
        search = request.form.get('ghgh').strip()
        query = "SELECT id, maori_name, english_name, definition, img_src, category FROM words WHERE maori_name like ? or english_name like ?"
        search = "%" + search + "%"
        words = db_fetch_or_commit(query, (search, search,), False)

        if not bool(words):
            return redirect_and_flash('/', f"There are no words related to {search.strip('%')}")
        # this code has to use .lower() for the format so that it is in lowercase's like the file name is.
        return render_template("words-category.html", logged_in=check_log_in_status(), words=words,
                               category_list=get_all_categories())
    elif request.method == 'GET':
        return redirect_and_flash('/', "Cant enter URL manually!")


@app.route('/signup', methods=['POST', 'GET'])
def render_signup():
    if check_log_in_status()[0]:
        return redirect_and_flash('/', "You are already logged in!")
    if request.method == 'POST':
        print(request.form)
        user_name = request.form.get('user_name').strip()
        email = request.form.get('email_address').strip()
        user_type = request.form['qualification']
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        if password1 != password2:
            return redirect_and_flash('/signup', 'Passwords do not match')

        hashed_password = bcrypt.generate_password_hash(password1)
        print(user_name, email, password1, user_type, hashed_password)

        query = "INSERT INTO users (name, email, password, user_type) VALUES (?, ?, ?, ?)"

        try:
            db_fetch_or_commit(query, (user_name, email, hashed_password, user_type), True)
        except sqlite3.IntegrityError:
            return redirect_and_flash('/signup', 'This email is already being used')

        return redirect_and_flash('/login', 'Signup Successful!')

    return render_template('signup.html', min_password=MIN_PASSWORD_LENGTH, password_regex=PASSWORD_REGEX_REQUIREMENTS,
                           user_name_regex=USER_NAME_REGEX_REQUIREMENTS, logged_in=check_log_in_status(),
                           category_list=get_all_categories())


@app.route('/login', methods=["POST", "GET"])
def render_login():
    if check_log_in_status()[0]:
        return redirect_and_flash('/', "You are already logged in!")
    if request.method == 'POST':
        email = request.form['email_address'].strip().lower()
        password = request.form['password'].strip()

        query = "SELECT id, name, password, user_type  FROM users WHERE email = ?"
        user_data = db_fetch_or_commit(query, (email,), False)
        if user_data is None:
            return redirect_and_flash('/login', 'Email Invalid')

        try:
            user_id = user_data[0][0]
            user_name = user_data[0][1]
            db_password = user_data[0][2]
            user_type = user_data[0][3]
        except IndexError:
            return redirect_and_flash('/login', 'email invalid or password incorrect')

        if not bcrypt.check_password_hash(db_password, password):
            return redirect_and_flash(request.referrer + "?error=Password+incorrect", 'password incorrect')

        session['email'] = email
        session['user_id'] = user_id
        session["name"] = user_name
        session["user_type"] = user_type
        print(session)

        return redirect_and_flash('/', 'Logged In!')

    return render_template('login.html', logged_in=check_log_in_status(), category_list=get_all_categories())


@app.route('/logout')
def logout():
    print(list(session.keys()))
    [session.pop(key) for key in list(session.keys())]
    print(list(session.keys()))
    return redirect_and_flash('/', "See you next time!")


@app.route('/admin')
def admin():
    if not check_log_in_status()[1]:
        return redirect_and_flash('/', "Need to be logged in as teacher!")

    return render_template('admin.html', logged_in=check_log_in_status(), levels=LEVELS, categories=get_all_categories(),
                           category_list=get_all_categories())


@app.route('/delete-category', methods=['POST', 'GET'])
def delete_category():
    if not check_log_in_status()[1]:
        return redirect_and_flash('/', "Need to be logged in as teacher!")
    category_to_delete = request.form.get('cat_id')

    # delete the images
    query = "SELECT img_src FROM words WHERE category = ?"
    category_img_paths = db_fetch_or_commit(query, (category_to_delete,), False)
    for word_data in category_img_paths:
        os.remove(f'static/images/{word_data[0]}')

    # delete words in that category
    query = "DELETE FROM words WHERE category = ?"
    db_fetch_or_commit(query, (category_to_delete,), True)

    # delete the category itself
    query = "DELETE FROM categories WHERE id = ?"
    db_fetch_or_commit(query, (category_to_delete,), True)

    flash(f'{category_to_delete} Category Deleted!')
    return redirect('/admin')


@app.route('/add-category', methods=['POST', 'GET'])
def add_category():
    if not check_log_in_status()[1]:
        return redirect_and_flash('/', "Need to be logged in as teacher!")
    if request.method == 'POST':
        print(request.form)
        category_name = request.form.get('category_name')
        query = "INSERT INTO categories (category) VALUES (?)"
        try:
            db_fetch_or_commit(query, (category_name,), True)
        except sqlite3.IntegrityError:
            return redirect_and_flash('/admin', "This category already exists!")
        return redirect_and_flash('/admin', "Category Added!")
    elif request.method == 'GET':
        return redirect_and_flash('/', "cant enter URL manually!")


@app.route('/add-word', methods=['POST', 'GET'])
def add_word():
    if not check_log_in_status()[1]:
        return redirect_and_flash('/', "Need to be logged in as teacher!")
    if request.method == 'POST':
        print(request.form)
        maori_word = request.form.get('maori_word')  #
        english_word = request.form.get('english_word')  #
        definition = request.form.get('definition')  #
        year_level = request.form.get('level_id')  #
        category = request.form.get('cat_id')
        category = category.split(", ")
        category_id = category[0]  #
        file = request.files['image_file']
        image_src = secure_filename(file.filename)  #
        file.save(os.path.join(app.config['UPLOAD'], image_src))
        # Make sure to check if file already exists and don't add the file if it does.
        author = session.get("user_id")
        time_of_entry = datetime.now()

        query = "SELECT * FROM words WHERE maori_name = ? AND english_name = ?"
        word_already_exits = db_fetch_or_commit(query, (maori_word, english_word), False)

        if not word_already_exits:
            query = "INSERT INTO words (maori_name, english_name, definition, img_src, last_edit_time, author_of_entry, year_level, category) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            db_fetch_or_commit(query, (
                maori_word, english_word, definition, image_src, time_of_entry, author, year_level, category_id), True)
        else:
            return redirect_and_flash('/admin', 'This word with the same meaning already exits!')

        return redirect_and_flash('admin', 'Word Added!')
    elif request.method == 'GET':
        return redirect_and_flash('/', "Cant enter URL manually!")


@app.route('/words/<word_id>')
def render_word(word_id):
    if not check_log_in_status()[0]:
        return redirect_and_flash('/', "Need to be logged in as a teacher or student!")
    query = "SELECT words.id, words.maori_name, words.english_name, words.definition, words.img_src, words.last_edit_time, users.name, words.year_level, words.category, categories.category FROM words INNER JOIN users ON words.author_of_entry=users.id INNER JOIN categories ON words.category=categories.id WHERE words.id = ?"

    word_list = db_fetch_or_commit(query, (word_id,), False)
    print(word_list)

    if not bool(word_list):
        return redirect_and_flash('/', "That word doesn't exist!")
    return render_template('word.html', logged_in=check_log_in_status(), category_list=get_all_categories(),
                           word_list=word_list, levels=LEVELS)


@app.route('/categories/<category>/')
def render_category(category):
    if not check_log_in_status()[0]:
        return redirect_and_flash('/', "Need to be logged in as a teacher or student!")

    query = "SELECT id, maori_name, english_name, definition, img_src, category FROM words where category = ?"
    words_list = db_fetch_or_commit(query, (category,), False)
    print(words_list)
    if not bool(words_list):
        return redirect_and_flash('/', "This category doesnt have anything to view in it yet")

    return render_template('words-category.html', logged_in=check_log_in_status(), words=words_list,
                           category_list=get_all_categories())


@app.errorhandler(404)
def page_not_found(e):
    print(e)
    return render_template('404Error.html', logged_in=check_log_in_status()), 404


if __name__ == '__main__':
    app.run()
