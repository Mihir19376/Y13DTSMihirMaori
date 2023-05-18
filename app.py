from flask import Flask, render_template, redirect, request, session, flash
from werkzeug.utils import secure_filename
import sqlite3
from sqlite3 import Error
from flask_bcrypt import Bcrypt
import os
from datetime import datetime

# ---Setting up the App---
DATABASE = "maoridictionary.db"  # Assign dictionary db path to variable for connection reference late on.
app = Flask(__name__)  # Initialise the Flask app.
bcrypt = Bcrypt(app)  # Initialise the encryption app.
app.secret_key = "ueuywq9571"  # Secret De/Encryption Key for scrambling the passwords.
upload = 'static/images'  # File path to the folder where to upload and store the words reference images.
app.config['UPLOAD'] = upload  # Setting the upload destination that my program uses to the upload file path.

# ---Constants---
LEVELS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]  # The year level meant for each word.

TEACHER_USER_TYPE = 2  # Setting the user type for the teacher to the number 2 to correlate with the number in the db
STUDENT_USER_TYPE = 1  # Setting the user type for the student to the number 1 to correlate with the number in the db

PASSWORD_REGEX_REQUIREMENTS = "^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9]).*$"  # password requirements - must have 1
# lowercase, 1 uppercase, and one number
USER_NAME_REGEX_REQUIREMENTS = "^[\w'\-,.][^0-9_!¡?÷?¿/\\+=@#$%ˆ&*(){}|~<>;:[\]]{2,}$"  # user_name requirements -
# cant have any special characters except for "-" and "'" and "." and " "
WORD_REGEX_REQUIREMENTS = "^[a-zA-Z\s'-]+$"  # The word cannot have any special characters or numbers bar the '-', ' ',
# and '''

# ---User Input Boundary Constraints---
MINIMUM_CHARS = 2  # The minimum input across all inputs.
MAX_MAORI_WORD_CHARS = 89  # Maximum characters for a Maori Word.
MAX_ENGLISH_WORD_CHARS = 45  # Maximum characters for an English Word.
MAX_DEFINITION_CHARS = 500  # Maximum characters for a definition.
MAX_IMAGE_SOURCE_CHARS = 60  # Maximum characters for an image source path.
MAX_NAME_CHARS = 45  # Maximum characters for a users name.
MAX_EMAIL_CHARS = 60  # Maximum characters for a users email address.
MAX_PASSWORD_CHARS = 72  # Maximum characters for a password.
MAX_CATEGORY_CHARS = 45  # Maximum characters for a category name
MIN_PASSWORD_CHARS = 8  # Minimum amount of characters in a password.


# ---Functions---


def redirect_and_flash(redirect_url, flash_message):
    """
    The redirect_and_flash function will redirect the site to the given url and flash a message that the html will pick
     up and display
    :param redirect_url: The url string you wish to redirect the site to
    :param flash_message: The message string you wish to display once they are redirected
    :return: a redirect statement that redirects the site to the given url
    """
    flash(flash_message)  # this will send the message out and the base.html will pick it up and display it
    return redirect(redirect_url)  # this will redirect the website to the given url


def check_log_in_status():
    """
    This function will check what log in status the user is in and return a list that signifies their status. The first
    element within the list will be a boolean stating if they are in fact logged in at all (True) or not (False) and the
    second entry will represent if they are logged in as a teacher (True) or not (False). This functioned is called
    everytime the site is loaded on any page.
    :return: List containing the two booleans signifying the login status of the current user.
    """
    # If there is no email in their log in session then continue
    if session.get("email") is None:
        print("not logged in")
        return [False, False]  # return "Not logged in" & "Not Teacher"
    # If there is an email then continue:
    else:
        print('Logged In')
        return [True, session.get("user_type") == TEACHER_USER_TYPE]  # Return "Logged in" & "Not Teacher" or "Teacher"


def open_database(db_name):
    """
    the open_database function will create a connection with the sqlite3 database it is provided with.
    :param db_name: The name of the database you want to access and make a connection to
    :return: The connection to the database
    """
    try:  # Try making a connection
        connection = sqlite3.connect(db_name)  # Create a connection with the sqlite3 db
        return connection  # return said connection
    except Error as e:  # if the connection doesn't occur, store the error as e
        print(e)  # and print the error
    return None  # If the function gets up to here, then there was no connection made, and it will return None


def db_fetch_or_commit(query_string, query_parameters, push):
    """
    this function will commit or fetch from the database
    :param query_string: this string is the SQL query you wish to execute.
    :param query_parameters: This tuple is the values to enter into SQL query if there are some.
    :param push: This is a boolean that states whether this is a push (commit) or not (fetch)
    :return: The list of fetched times (if this is a fetch)
    """
    con = open_database(DATABASE)  # store the connection with the database in a variable
    cur = con.cursor()  # the cursor is what can edit and view the db, and we store the curser in a variable.
    if not query_parameters:  # if there is no query parameters provided, then it will:
        cur.execute(query_string)  # just execute the string.
        print("monkey")
    else:  # But if there are parameters:
        cur.execute(query_string, query_parameters)  # it'll execute the code with thew parameters as well

    if not push:  # if the query is not a push query, then it'll fetch the data and return it
        data = cur.fetchall()  # fetch the data from the cursor
        con.close()
        return data  # and return it
    else:  # but if it is a push statement, it'll commit it
        con.commit()
        con.close()


def get_all_categories():
    """
    This will fetch all the categories in the db
    :return: the list of all the categories
    """
    # this will fetch all the category names and their id's from the categories table
    query = "SELECT id, category FROM categories"
    category_list = db_fetch_or_commit(query, None, False)
    return category_list


# ---App Routes and their associated functions---

@app.route('/')
def render_home():
    """
    Render the homepage...
    """
    return render_template('home.html', logged_in=check_log_in_status(), category_list=get_all_categories())


@app.route('/delete-word', methods=['POST', 'GET'])
def delete_word():
    """
    This function deletes a given word from the db and their image from the files
    """
    # if the second boolean is false, then they aren't a teacher and will be warned and redirected home
    if not check_log_in_status()[1]:
        redirect_and_flash('/', 'Need to be logged in as teacher!')
    # if the method that the app route was entered in was because of post:
    if request.method == 'POST':
        print(request.form)
        deletion_id = request.form.get('deletion_id')  # retrieve the id to be deleted from the form

        # delete the image of the word
        query = "SELECT img_src FROM words where id = ?"
        image_to_delete = db_fetch_or_commit(query, (deletion_id, ), False)[0][0]
        # os.remove(f'static/images/{image_to_delete}')  # delete it

        # delete the row with the deletion id
        query = "DELETE FROM words WHERE id = ?"
        db_fetch_or_commit(query, (deletion_id,), True)

        return redirect_and_flash('/', 'Word Deleted')
    elif request.method == 'GET':  # if the method was a get (url entered manually):
        return redirect_and_flash('/', 'Cant enter URL manually!')


@app.route('/edit-word', methods=['POST', 'GET'])
def edit_word():
    """
    This function edits all the credentials of a given word
    """
    # if the second boolean is false, then they aren't a teacher and will be warned and redirected home
    if not check_log_in_status()[1]:
        return redirect_and_flash('/', "Need to be logged in as teacher!")
    if request.method == 'POST':
        print(request.form)
        # retrieve the [] from the submitted form by searching for their ids
        old_image = request.form.get('previous_img_src')  # [the old images file name]
        word_id = request.form.get('id')  # [the id of the word]
        maori_word = request.form.get('maori_word')  # [the words maori name]
        english_word = request.form.get('english_word')  # [the words english name]
        definition = request.form.get('definition')  # [the definition]
        year_level = request.form.get('level_id')  # [the year level]
        category_id = request.form.get('cat_id')  # [the category id]

        author = session.get("user_id")  # retrieve the id of the user who edited by checking the session credentials

        time_of_entry = datetime.now()  # retrieve the current date and time

        image_file = request.files['image_file']  # retrieve the file form the form
        image_src = secure_filename(image_file.filename)  # retrieve the image name/src from the file

        # fetch all the rows from the words table that name this maori&english name but doesn't have the current id
        query = "SELECT * FROM words WHERE maori_name = ? AND english_name = ? AND NOT id = ?"
        # convert the list into a boolean, if the list is empty is will be False and vice versa
        word_already_exits = bool(db_fetch_or_commit(query, (maori_word, english_word, word_id), False))

        # if there isn't data in the list then that means there aren't any duplicates.
        if not word_already_exits:
            # Update all but the img source with the new ones retrieved.
            query = "UPDATE words SET maori_name = ?, english_name = ?, definition = ?, last_edit_time = ?, " \
                    "author_of_entry = ?, year_level = ?, category = ? WHERE id = ?"
            db_fetch_or_commit(query, (
                maori_word, english_word, definition, time_of_entry, author, year_level, category_id, word_id,), True)

            # if the new image source doesn't contain anything, then redirect them back to the word.
            if not image_src:
                return redirect_and_flash(f'/words/{word_id}', 'Updated!')
            else:  # but if it does contain something then:
                print(image_src)
                if old_image != "no-image-available.png" and old_image != '':  # if the old image wasn't these two then:
                    os.remove(f'static/images/{old_image}')  # delete it
                image_file.save(os.path.join(app.config['UPLOAD'], image_src))  # save the new image file to the images folder
                # Update the image source of the word
                query = "UPDATE words SET img_src = ? WHERE id = ?"
                db_fetch_or_commit(query, (image_src, word_id,), True)

                return redirect_and_flash(f'/words/{word_id}', 'Updated!')
        else:  # if this si duplicate:
            return redirect_and_flash('/', 'This word with the same meaning already exits!')
    elif request.method == 'GET':  # if they entered this url in manually:
        return redirect_and_flash('/', 'Cant enter URL manually!')


@app.route("/search", methods=["GET", "POST"])
def render_search():
    """
     the search function displays the words the user searches for
    """
    if request.method == 'POST':
        print(request.form)
        search = request.form.get('search_query').strip()  # remove any trailing spaces from the search
        search = "%" + search + "%"  # this is just to make sure that it recognises words with the word search properly
        # fetch all but the author, year level, and category of the words that's have a maori or english name that is
        # like the search
        query = "SELECT id, maori_name, english_name, definition, img_src, category FROM words WHERE maori_name like " \
                "? or english_name like ?"
        words = db_fetch_or_commit(query, (search, search,), False)

        if not bool(words):  # if the list of words is empty then redirect the user back home and notify them
            return redirect_and_flash('/', f"There are no words related to {search.strip('%')}")
        # display all the words if there were any
        return render_template("words-category.html", logged_in=check_log_in_status(), words=words,
                               category_list=get_all_categories())
    elif request.method == 'GET':  # if they entered this url in manually:
        return redirect_and_flash('/', "Cant enter URL manually!")


@app.route('/signup', methods=['POST', 'GET'])
def render_signup():
    """
    the sign-up function signs up the user to the database/website
    """
    if check_log_in_status()[0]:  # if the first value of the lig in status is true then they are already logged in so:
        return redirect_and_flash('/', "You are already logged in!")

    if request.method == 'POST':
        print(request.form)
        user_name = request.form.get('user_name').strip()  # get the users name and trip any trailing spaces
        email = request.form.get('email_address').strip()  # same deal for the email
        user_type = request.form['qualification']  # retrieve their qualification (teacher/student)
        password1 = request.form.get('password1')  # retrieve the first password
        password2 = request.form.get('password2')  # retrieve the second one

        if password1 != password2:  # if the first one doest match uo with the second password then:
            return redirect_and_flash('/signup', 'Passwords do not match')

        hashed_password = bcrypt.generate_password_hash(password1)  # generate an encrypted password for them
        print(user_name, email, password1, user_type, hashed_password)

        # insert all the gathered credentials into the users table.
        query = "INSERT INTO users (name, email, password, user_type) VALUES (?, ?, ?, ?)"
        try:
            db_fetch_or_commit(query, (user_name, email, hashed_password, user_type), True)
        except sqlite3.IntegrityError:  # this means that there is a duplicate email:
            return redirect_and_flash('/signup', 'This email is already being used')

        # if they get up to here:
        return redirect_and_flash('/login', 'Signup Successful!')

    return render_template('signup.html', min_password=MIN_PASSWORD_CHARS, password_regex=PASSWORD_REGEX_REQUIREMENTS,
                           user_name_regex=USER_NAME_REGEX_REQUIREMENTS, logged_in=check_log_in_status(),
                           category_list=get_all_categories(), max_email=MAX_EMAIL_CHARS, max_name=MAX_NAME_CHARS)


@app.route('/login', methods=["POST", "GET"])
def render_login():
    """
    the longin function will render the login page and also log the user into the website
    """
    if check_log_in_status()[0]:  # if the first value of the lig in status is true then they are already logged in so:
        return redirect_and_flash('/', "You are already logged in!")
    if request.method == 'POST':
        email = request.form['email_address'].strip().lower()
        password = request.form['password'].strip()

        # fetch all the but the email from the row in the users table where the email matches the retrieved one
        query = "SELECT id, name, password, user_type  FROM users WHERE email = ?"
        user_data = db_fetch_or_commit(query, (email,), False)
        if user_data is None:  # if nothing is in the fetched list then:
            return redirect_and_flash('/login', 'Email Invalid')

        try:  # assign all the received data from the list in variables
            user_id = user_data[0][0]
            user_name = user_data[0][1]
            db_password = user_data[0][2]
            user_type = user_data[0][3]
        except IndexError:  # if one of the values trying to be extracted above doesn't exist then:
            return redirect_and_flash('/login', 'email invalid or password incorrect')

        if not bcrypt.check_password_hash(db_password, password):  # if de-scrambled password and the input don't match
            return redirect_and_flash(request.referrer + "?error=Password+incorrect", 'password incorrect')

        # create an email, user_id, name, and user_type variable assigned accordingly and store it in the session
        session['email'] = email
        session['user_id'] = user_id
        session["name"] = user_name
        session["user_type"] = user_type
        print(session)

        return redirect_and_flash('/', 'Logged In!')

    return render_template('login.html', logged_in=check_log_in_status(), category_list=get_all_categories(),
                           min_password=MIN_PASSWORD_CHARS)


@app.route('/logout')
def logout():
    """
    the logout function logs out the user by clearing the session
    """
    print(list(session.keys()))
    [session.pop(key) for key in list(session.keys())]  # clear the session - delete (pop) all the elements in the list
    print(list(session.keys()))
    return redirect_and_flash('/', "See you next time!")


@app.route('/admin')
def admin():
    """
    This function renders the admin page
    """
    if not check_log_in_status()[1]:  # if they aren't logged in as a teacher:
        return redirect_and_flash('/', "Need to be logged in as teacher!")

    return render_template('admin.html', logged_in=check_log_in_status(), levels=LEVELS,
                           categories=get_all_categories(),
                           category_list=get_all_categories(), max_maori=MAX_MAORI_WORD_CHARS,
                           max_english=MAX_ENGLISH_WORD_CHARS, max_definition=MAX_DEFINITION_CHARS, word_regex=WORD_REGEX_REQUIREMENTS)


@app.route('/delete-category', methods=['POST', 'GET'])
def delete_category():
    """
    the deletes category function delete the given category and all its contents
    """
    if not check_log_in_status()[1]:  # if they aren't logged is as a teacher
        return redirect_and_flash('/', "Need to be logged in as teacher!")

    category_to_delete = request.form.get('cat_id')  # retrieve the category to delete

    # retrieve and delete all the images that are stored in the categories words
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

    return redirect_and_flash('/admin', f'{category_to_delete} Category Deleted!')


@app.route('/add-category', methods=['POST', 'GET'])
def add_category():
    """
    This function adds categories to the db
    """
    if not check_log_in_status()[1]:  # if they aren't logged is as a teacher:
        return redirect_and_flash('/', "Need to be logged in as teacher!")
    if request.method == 'POST':
        print(request.form)
        category_name = request.form.get('category_name')  # retrieve category name

        # insert his category into the categories table
        query = "INSERT INTO categories (category) VALUES (?)"
        try:
            db_fetch_or_commit(query, (category_name,), True)
        except sqlite3.IntegrityError:  # if that flares an integrity error this is because the column is set to
            # unique, so it means that the category input is a duplicate:
            return redirect_and_flash('/admin', "This category already exists!")
        return redirect_and_flash('/admin', "Category Added!")
    elif request.method == 'GET':
        return redirect_and_flash('/', "cant enter URL manually!")


@app.route('/add-word', methods=['POST', 'GET'])
def add_word():
    """
    this function adds a word to the db
    :return:
    """
    if not check_log_in_status()[1]:  # if they aren't logged is as a teacher:
        return redirect_and_flash('/', "Need to be logged in as teacher!")
    if request.method == 'POST':
        print(request.form)

        # retrieve the following from the form (self-explanatory)
        maori_word = request.form.get('maori_word')
        english_word = request.form.get('english_word')
        definition = request.form.get('definition')
        year_level = request.form.get('level_id')
        category = request.form.get('cat_id')

        category = category.split(", ")  # split it up into the id and name
        category_id = category[0]

        image_file = request.files['image_file']
        image_src = secure_filename(image_file.filename)
        # no need to check if already exists because the code ignore this is it does
        image_file.save(os.path.join(app.config['UPLOAD'], image_src))

        author = session.get("user_id")  # retrieve the authors id from the session cache
        time_of_entry = datetime.now()  # retrieve the current date and time

        # retrieve all the credentials of the word where the maori name and english name match what the users entered
        query = "SELECT * FROM words WHERE maori_name = ? AND english_name = ?"
        word_already_exits = db_fetch_or_commit(query, (maori_word, english_word), False)

        if not word_already_exits:  # if there isn't any duplicates then:
            # insert all the credentials gathered into the words table
            query = "INSERT INTO words (maori_name, english_name, definition, img_src, last_edit_time, " \
                    "author_of_entry, year_level, category) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            db_fetch_or_commit(query, (
                maori_word, english_word, definition, image_src, time_of_entry, author, year_level, category_id), True)
        else:  # but if there was a duplicate, then:
            return redirect_and_flash('/admin', 'This word with the same meaning already exits!')

        return redirect_and_flash('admin', 'Word Added!')
    elif request.method == 'GET':
        return redirect_and_flash('/', "Cant enter URL manually!")


@app.route('/words/<word_id>')
def render_word(word_id):
    """
    this function displays a single word and its credentials
    :param word_id:
    :return:
    """
    if not check_log_in_status()[0]:  # if not logged in at all, then:
        return redirect_and_flash('/', "Need to be logged in as a teacher or student!")

    # fetch the words: all the words credentials and the name of the users correlated with the author id, and category
    # name correlated with the cat id.
    query = "SELECT words.id, words.maori_name, words.english_name, words.definition, words.img_src, " \
            "words.last_edit_time, users.name, words.year_level, words.category, categories.category " \
            "FROM words INNER JOIN users ON words.author_of_entry=users.id INNER JOIN categories ON " \
            "words.category=categories.id WHERE words.id = ?"
    word_list = db_fetch_or_commit(query, (word_id,), False)
    print(word_list)

    if not bool(word_list):  # if the list is emtpy then:
        return redirect_and_flash('/', "That word doesn't exist!")

    return render_template('word.html', logged_in=check_log_in_status(), category_list=get_all_categories(),
                           word_list=word_list, levels=LEVELS, max_maori=MAX_MAORI_WORD_CHARS,
                           max_english=MAX_ENGLISH_WORD_CHARS, max_definition=MAX_DEFINITION_CHARS, word_regex=WORD_REGEX_REQUIREMENTS)


@app.route('/categories/<category>/')
def render_category(category):
    if not check_log_in_status()[0]:  # if not logged in at all, then:
        return redirect_and_flash('/', "Need to be logged in as a teacher or student!")

    # select the all but the edit time, author, year leve, and category from the words table given the given category
    query = "SELECT id, maori_name, english_name, definition, img_src FROM words where category = ?"
    words_list = db_fetch_or_commit(query, (category,), False)
    print(words_list)

    # select the category that this url is viewing
    query = "SELECT category FROM categories WHERE id = ?"
    selected_cat = db_fetch_or_commit(query, (category, ), False)

    if not bool(words_list):  # if there are no words in that category
        return redirect_and_flash('/', "This category doesnt have anything to view in it yet")

    return render_template('words-category.html', logged_in=check_log_in_status(), words=words_list,
                           category_list=get_all_categories(), selected_cat=selected_cat[0][0])


@app.errorhandler(404)
def page_not_found(e):
    """
    this function handles the infamous 404 error where the url is not found within the program and renders the 404 error
    page
    :param e: the error
    """
    print(e)
    return render_template('404Error.html', logged_in=check_log_in_status(), category_list=get_all_categories()), 404


if __name__ == '__main__':
    app.run()
