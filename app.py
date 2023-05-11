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


def fetch_from_database(query_string):
    query = query_string

def get_all_categories():
    query = "SELECT id, category FROM categories"
    con = open_database(DATABASE)
    cur = con.cursor()
    cur.execute(query)
    category_list = cur.fetchall()
    # category_list = [category[0] for category in category_list]
    con.close()
    return category_list


def is_logged_in_as_teacher():
    if session.get("email") is None:
        print("not logged in")
        return [False, False]
    else:
        if session.get("user_type") == TEACHER_USER_TYPE:
            print("logged in")
            # logged in is true, and as teacher is true
            return [True, True]
        elif session.get("user_type") == STUDENT_USER_TYPE:
            # logged in is true, but as teacher is false
            return [True, False]


def open_database(db_name):
    try:
        connection = sqlite3.connect(db_name)
        return connection
    except Error as e:
        print(e)
    return None


@app.route('/delete-word', methods=['POST', 'GET'])
def delete_word():
    if not is_logged_in_as_teacher()[1]:
        flash("Need to be logged in as teacher!")
        return redirect('/?message=Need+to+be+logged+in+as+teacher')
    if request.method == 'POST':
        print(request.form)
        id = request.form.get('deletion_id')
        query = "DELETE FROM words WHERE id = ?"
        con = open_database(DATABASE)
        cur = con.cursor()
        cur.execute(query, (id, ))
        con.commit()
        con.close()
        flash("Word Deleted")
        return redirect('/')
    elif request.method == 'GET':
        flash("Cant enter URL manually!")
        return redirect('/?message=cant+enter+url+manually')


@app.route('/edit-word', methods=['POST', 'GET'])
def edit_word():
    if not is_logged_in_as_teacher()[1]:
        flash("Need to be logged in as teacher!")
        return redirect('/?message=Need+to+be+logged+in+as+teacher')

    if request.method == 'POST':
        print(request.form)
        con = open_database(DATABASE)
        cur = con.cursor()
        old_image = request.form.get('previous_img_src')
        word_id = request.form.get('id')
        maori_word = request.form.get('maori_word')  #
        english_word = request.form.get('english_word')  #
        definition = request.form.get('definition')  #
        year_level = request.form.get('level_id')  #
        category = request.form.get('cat_id')
        author = session.get("user_id") #
        time_of_entry = datetime.now() #
        file = request.files['image_file']
        image_src = secure_filename(file.filename) #

        con = open_database(DATABASE)
        query = f"SELECT * FROM words WHERE maori_name = ? AND english_name = ? AND NOT id = ?"
        cur = con.cursor()
        cur.execute(query, (maori_word, english_word, word_id))
        word_already_exits = bool(cur.fetchall())
        # con.close()

        if not word_already_exits:
            query = "UPDATE words SET maori_name = ?, english_name = ?, definition = ?, last_edit_time = ?, author_of_entry = ?, year_level = ?, category = ? WHERE id = ?"
            cur.execute(query, (maori_word, english_word, definition, time_of_entry, author, year_level, category, word_id, ))
            con.commit()
            if image_src == "":
                con.close()
                flash('Updated!')
                return redirect(f'/categories/{category}/{word_id}')
            else:
                print(image_src)
                file.save(os.path.join(app.config['UPLOAD'], image_src))
                query = "UPDATE words SET img_src = ? WHERE id = ?"
                cur.execute(query, (image_src, word_id, ))
                con.commit()
                con.close()
                if old_image != "no-image-available.png" and old_image != '':
                    os.remove(f'static/images/{old_image}')
                flash('Updated!')
                return redirect(f'/categories/{category}/{word_id}')
        else:
            con.close()
            flash('This word with the same meaning already exits!')
            return redirect('/')
    elif request.method == 'GET':
        flash("Cant enter URL manually!")
        return redirect('/?message=you+cant+access+manually')


@app.route('/')
def render_home():  # put application's code here
    return render_template('home.html', logged_in=is_logged_in_as_teacher(), category_list=get_all_categories())


@app.route("/search", methods=["GET", "POST"])
def render_search():
    if request.method == 'POST':
        print(request.form)
        search = request.form.get('ghgh').strip()
        print(search)
        query = "SELECT id, maori_name, english_name, definition, img_src, category FROM words WHERE maori_name like ? or english_name like ?"
        search = "%" + search + "%"
        con = open_database(DATABASE)
        cur = con.cursor()
        cur.execute(query, (search, search, ))
        words = cur.fetchall()
        con.close()
        if not bool(words):
            flash(f"There are no words related to {search.strip('%')}")
            return redirect('/')
        # this code has to use .lower() for the format so that it is in lowercase's like the file name is.
        return render_template("words-category.html", logged_in=is_logged_in_as_teacher(), words=words, category_list=get_all_categories())
    elif request.method == 'GET':
        flash("cant enter URL manually!")
        return redirect('/?message=you+cant+access+manually')




@app.route('/signup', methods=['POST', 'GET'])
def render_signup():
    if is_logged_in_as_teacher()[0]:
        flash("You are already logged in!")
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

    return render_template('signup.html', min_password=MIN_PASSWORD_LENGTH, password_regex=PASSWORD_REGEX_REQUIREMENTS,
                           user_name_regex=USER_NAME_REGEX_REQUIREMENTS, logged_in=is_logged_in_as_teacher(),
                           category_list=get_all_categories())


@app.route('/login', methods=["POST", "GET"])
def render_login():
    if is_logged_in_as_teacher()[0]:
        flash("Already logged in!")
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

    return render_template('login.html', logged_in=is_logged_in_as_teacher(), category_list=get_all_categories())


@app.route('/logout')
def logout():
    print(list(session.keys()))
    [session.pop(key) for key in list(session.keys())]
    print(list(session.keys()))
    flash("See you next time!")
    return redirect('/?message=See+you+nest+time!')


@app.route('/admin')
def admin():
    if not is_logged_in_as_teacher()[1]:
        flash("Need to be logged in as teacher!")
        return redirect('/?message=Need+to+be+logged+in+as+teacher')

    # fetch all the categories from the database and add them to a list
    con = open_database(DATABASE)
    query = "SELECT * FROM categories ORDER BY category asc"
    cur = con.cursor()
    cur.execute(query)
    categories = cur.fetchall()
    con.close()

    return render_template('admin.html', logged_in=is_logged_in_as_teacher(), levels=LEVELS, categories=categories,
                           category_list=get_all_categories())


@app.route('/delete-category', methods=['POST', 'GET'])
def delete_category():
    if not is_logged_in_as_teacher()[1]:
        flash("Need to be logged in as teacher!")
        return redirect('/?message=Need+to+be+logged+in+as+teacher')
    category_to_delete = request.form.get('cat_id')
    # delete the images
    query = "SELECT img_src FROM words WHERE category = ?"
    con = open_database(DATABASE)
    cur = con.cursor()
    cur.execute(query, (category_to_delete,))
    category_word_datas = cur.fetchall()
    for word_data in category_word_datas:
        os.remove(f'static/images/{word_data[0]}')
    # delete words in that category
    query = "DELETE FROM words WHERE category = ?"
    con = open_database(DATABASE)
    cur = con.cursor()
    cur.execute(query, (category_to_delete,))
    con.commit()
    # delete the category itself
    query = "DELETE FROM categories WHERE id = ?"
    con = open_database(DATABASE)
    cur = con.cursor()
    cur.execute(query, (category_to_delete,))
    con.commit()

    con.close()
    return redirect('/admin')


@app.route('/add-category', methods=['POST', 'GET'])
def add_category():
    if not is_logged_in_as_teacher()[1]:
        flash("Need to be logged in as teacher!")
        return redirect('/?message=Need+to+be+logged+in+as+teacher')
    if request.method == 'POST':
        print(request.form)
        category_name = request.form.get('category_name')
        con = open_database(DATABASE)
        query = "INSERT INTO categories (category) VALUES (?)"
        cur = con.cursor()
        try:
            cur.execute(query, (category_name,))
        except sqlite3.IntegrityError:
            con.close()
            flash("This category already exists!")
            return redirect('/admin?message=category+already+exists')
        con.commit()
        con.close()
        flash('Category Added!')
        return redirect('/admin')
    elif request.method == 'GET':
        flash("cant enter URL manually!")
        return redirect('/?message=you+cant+access+manually')


@app.route('/add-word', methods=['POST', 'GET'])
def add_word():
    if not is_logged_in_as_teacher()[1]:
        flash("Need to be logged in as teacher!")
        return redirect('/?message=Need+to+be+logged+in+as+teacher')
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
        # CHECK IF THE FILE ALREADY EXITS AND DON'T LET THE FORM WORK IF IT DOES
        author = session.get("user_id")
        time_of_entry = datetime.now()

        # make sure to check if a duplicate words exits.
        # make sure that no word with the same maori name and same english name exits
        # but, that said, multiple entry's can have the same english name, and can also have the same maori name.

        con = open_database(DATABASE)
        query = "SELECT * FROM words WHERE maori_name = ? AND english_name = ?"
        cur = con.cursor()
        cur.execute(query, (maori_word, english_word))
        word_already_exits = bool(cur.fetchall())
        con.close()

        if not word_already_exits:
            con = open_database(DATABASE)
            query = "INSERT INTO words (maori_name, english_name, definition, img_src, last_edit_time, author_of_entry, year_level, category) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            cur = con.cursor()
            cur.execute(query, (
                maori_word, english_word, definition, image_src, time_of_entry, author, year_level, category_id))
        else:
            con.close()
            flash('This word with the same meaning already exits!')
            return redirect('/admin')
        con.commit()
        con.close()

        flash('Word Added!')
        return redirect('/admin')
    elif request.method == 'GET':
        flash("cant enter URL manually!")
        return redirect('/?message=you+cant+access+manually')


@app.route('/categories/<category>/<word_id>')
def render_word(category, word_id):
    if not is_logged_in_as_teacher()[0]:
        flash("Need to be logged in as a teacher or student!")
        return redirect('/?message=Need+to+be+logged+in')
    query = "SELECT words.id, words.maori_name, words.english_name, words.definition, words.img_src, words.last_edit_time, users.name, words.year_level, words.category, categories.category FROM words INNER JOIN users ON words.author_of_entry=users.id INNER JOIN categories ON words.category=categories.id WHERE words.id = ?"
    con = open_database(DATABASE)
    cur = con.cursor()
    cur.execute(query, (word_id, ))
    word_list = cur.fetchall()
    print(word_list)
    con.close()
    if not bool(word_list):
        flash("that word doesnt exist!")
        return redirect('/?message=word+doesnt+exist')
    return render_template('word.html', logged_in=is_logged_in_as_teacher(), category_list=get_all_categories(),
                           word_list=word_list, levels=LEVELS)


@app.route('/categories/<category>/')
def render_category(category):
    if not is_logged_in_as_teacher()[0]:
        flash("Need to be logged in as a teacher or student!")
        return redirect('/?message=Need+to+be+logged+in')
    query = "SELECT id, maori_name, english_name, definition, img_src, category FROM words where category = ?"
    con = open_database(DATABASE)
    cur = con.cursor()
    cur.execute(query, (category,))
    words_list = cur.fetchall()
    print(words_list)
    con.close()
    if not bool(words_list):
        flash("This category doesnt have anything to view in it yet")
        return redirect('/')
    return render_template('words-category.html', logged_in=is_logged_in_as_teacher(), words=words_list,
                           category_list=get_all_categories())


@app.errorhandler(404)
def page_not_found(e):
    print(e)
    return render_template('404Error.html', logged_in=is_logged_in_as_teacher()), 404


if __name__ == '__main__':
    app.run()
