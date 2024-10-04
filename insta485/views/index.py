"""
Insta485 index (main) view.

URLs include:
/
"""
import pathlib
import hashlib
import uuid
import flask
import arrow
import insta485

LOGGER = flask.logging.create_logger(insta485.app)


@insta485.app.route('/')
def show_index():
    """Display / route."""
    if "username" in flask.session:
        logname = flask.session["username"]
    else:
        return flask.redirect("/accounts/login/")
    # Connect to database
    connection = insta485.model.get_db()

    # Query database
    context = {"logname": logname}
    cur = connection.execute(
        "SELECT posts.postid, posts.owner, users.filename AS owner_img_url, "
        "posts.filename AS img_url, posts.created AS timestamp "
        "FROM posts JOIN users on posts.owner==users.username "
        "WHERE posts.owner in "
        "(SELECT username2 FROM following WHERE username1 == ?) "
        "or posts.owner == ? "
        "ORDER BY posts.postid DESC ",
        (logname, logname, )
    )
    posts = cur.fetchall()
    context["posts"] = posts

    for idx in range(len(posts)):
        time = arrow.get(context["posts"][idx]["timestamp"])
        context["posts"][idx]["timestamp"] = time.humanize()
        cur = connection.execute(
            "SELECT owner "
            "FROM likes "
            "WHERE postid == ? ",
            (context["posts"][idx]["postid"], )
        )
        likes = cur.fetchall()
        context["posts"][idx]["likes"] = len(likes)
        context["posts"][idx]["likes_list"] = [like["owner"] for like in likes]
        cur = connection.execute(
            "SELECT owner, text "
            "FROM comments "
            "WHERE postid == ? "
            "ORDER BY commentid ASC ",
            (context["posts"][idx]["postid"], )
        )
        comment = cur.fetchall()
        context["posts"][idx]["comments"] = comment

    return flask.render_template("index.html", **context)


@insta485.app.route('/uploads/<filename>')
def download_file(filename):
    """Download files."""
    _, status = auth()
    if status == 200:
        return flask.send_from_directory(
            insta485.app.config['UPLOAD_FOLDER'],
            filename
        )
    flask.abort(403)


@insta485.app.route('/users/<user_url_slug>/')
def show_user_url(user_url_slug):
    """GET /users/<user_url_slug>."""
    username = user_url_slug

    if "username" in flask.session:
        logname = flask.session["username"]
    else:
        return flask.redirect("/accounts/login/")

    # Connect to database
    connection = insta485.model.get_db()

    # Query database
    context = {"logname": logname, "username": username}
    cur = connection.execute(
        "SELECT username1 "
        "FROM following "
        "WHERE username1 == ? and username2 == ? ",
        (logname, username, )
    )
    logname_follows_username = cur.fetchall()
    context["logname_follows_username"] = len(logname_follows_username) != 0
    cur = connection.execute(
        "SELECT fullname "
        "FROM users "
        "WHERE username == ?",
        (username, )
    )
    name = cur.fetchall()
    context["fullname"] = name[0]["fullname"]
    cur = connection.execute(
        "SELECT COUNT(*) AS following "
        "FROM following "
        "WHERE username1 == ?",
        (username, )
    )
    name = cur.fetchall()
    context["following"] = name[0]["following"]
    cur = connection.execute(
        "SELECT COUNT(*) AS followers "
        "FROM following "
        "WHERE username2 == ? ",
        (username, )
    )
    name = cur.fetchall()
    context["followers"] = name[0]["followers"]
    cur = connection.execute(
        "SELECT postid, filename AS img_url "
        "FROM posts "
        "WHERE owner == ? "
        "ORDER BY postid ASC ",
        (username, )
    )
    posts = cur.fetchall()
    context["total_posts"] = len(posts)
    context["posts"] = posts

    return flask.render_template("user.html", **context)


@insta485.app.route('/users/<user_url_slug>/followers/')
def show_followers(user_url_slug):
    """GET /users/<user_url_slug>/followers/."""
    username = user_url_slug

    if "username" in flask.session:
        logname = flask.session["username"]
    else:
        return flask.redirect("/accounts/login/")

    # Connect to database
    connection = insta485.model.get_db()

    # Query database
    context = {"logname": logname, "username": username}
    cur = connection.execute(
        "SELECT following.username1 AS username, "
        "users.filename AS user_img_url "
        "FROM following JOIN users on following.username1"
        "==users.username "
        "WHERE following.username2 == ?",
        (username, )
    )
    followers = cur.fetchall()
    context["followers"] = followers
    cur = connection.execute(
        "SELECT username2 "
        "FROM following "
        "WHERE username1 == ?",
        (logname, )
    )
    logname_following = cur.fetchall()
    logname_following = [following["username2"]
                         for following in logname_following]
    for follower in context["followers"]:
        follower["logname_follows_username"] = (follower["username"]
                                                in logname_following)

    return flask.render_template("followers.html", **context)


@insta485.app.route('/users/<user_url_slug>/following/')
def show_following(user_url_slug):
    """GET /users/<user_url_slug>/following/."""
    username = user_url_slug

    if "username" in flask.session:
        logname = flask.session["username"]
    else:
        return flask.redirect("/accounts/login/")

    # Connect to database
    connection = insta485.model.get_db()

    # Query database
    context = {"logname": logname, "username": username}
    cur = connection.execute(
        "SELECT following.username2 AS username, "
        "users.filename AS user_img_url "
        "FROM following JOIN users on following.username2==users.username "
        "WHERE following.username1 == ?",
        (username, )
    )
    following = cur.fetchall()
    context["following"] = following
    cur = connection.execute(
        "SELECT username2 "
        "FROM following "
        "WHERE username1 == ?",
        (logname, )
    )
    logname_following = cur.fetchall()
    logname_following = [following["username2"]
                         for following in logname_following]
    for follow in context["following"]:
        follow["logname_follows_username"] = (follow["username"]
                                              in logname_following)

    return flask.render_template("following.html", **context)


@insta485.app.route('/posts/<postid_url_slug>/')
def show_post(postid_url_slug):
    """GET /posts/<postid_url_slug>/."""
    postid = int(postid_url_slug)

    if "username" in flask.session:
        logname = flask.session["username"]
    else:
        return flask.redirect("/accounts/login/")
    # Connect to database
    connection = insta485.model.get_db()

    # Query database
    context = {"logname": logname, "postid": postid}
    cur = connection.execute(
        "SELECT posts.owner AS owner, users.filename AS owner_img_url, "
        "posts.filename AS img_url, posts.created AS timestamp "
        "FROM posts JOIN users on posts.owner==users.username "
        "WHERE posts.postid == ?",
        (postid, )
    )
    post = cur.fetchall()
    context["owner"] = post[0]["owner"]
    context["owner_img_url"] = post[0]["owner_img_url"]
    context["img_url"] = post[0]["img_url"]
    context["timestamp"] = arrow.get(post[0]["timestamp"]).humanize()
    cur = connection.execute(
        "SELECT owner "
        "FROM likes "
        "WHERE likes.postid == ?",
        (postid, )
    )
    likes = cur.fetchall()
    context["likes"] = len(likes)
    context["like_list"] = [like["owner"] for like in likes]
    cur = connection.execute(
        "SELECT commentid, owner, text "
        "FROM comments "
        "WHERE comments.postid == ? "
        "ORDER BY commentid ASC ",
        (postid, )
    )
    comments = cur.fetchall()
    context["comments"] = comments

    return flask.render_template("post.html", **context)


@insta485.app.route('/explore/')
def show_explore():
    """GET /explore/."""
    # Connect to database
    connection = insta485.model.get_db()

    if "username" in flask.session:
        logname = flask.session["username"]
    else:
        return flask.redirect("/accounts/login/")

    # Query database
    context = {"logname": logname}
    cur = connection.execute(
        "SELECT username AS username, filename AS user_img_url "
        "FROM users "
        "WHERE username not in "
        "(SELECT username2 FROM following WHERE username1 == ?) "
        "and username != ?",
        (logname, logname, )
    )
    not_following = cur.fetchall()
    context["not_following"] = not_following

    return flask.render_template("explore.html", **context)


@insta485.app.route('/accounts/login/')
def login():
    """Login page."""
    if "username" in flask.session:
        return flask.redirect("/")
    return flask.render_template("login.html")


@insta485.app.route('/accounts/create/')
def create():
    """Create Account Page."""
    if "username" in flask.session:
        return flask.redirect("/accounts/edit/")
    return flask.render_template("create.html")


@insta485.app.route('/accounts/delete/')
def delete():
    """Delete Account Page."""
    if "username" in flask.session:
        logname = flask.session["username"]
    else:
        return flask.redirect("/accounts/login/")
    context = {"logname": logname}
    return flask.render_template("delete.html", **context)


@insta485.app.route('/accounts/edit/')
def edit():
    """Edit Account Page."""
    if "username" in flask.session:
        logname = flask.session["username"]
    else:
        return flask.redirect("/accounts/login/")
    context = {"logname": logname}
    connection = insta485.model.get_db()
    cur = connection.execute(
        "SELECT filename, fullname, email "
        "FROM users "
        "WHERE username == ? ",
        (logname, )
    )
    user = cur.fetchall()
    user = user[0]
    context["filename"] = user["filename"]
    context["fullname"] = user["fullname"]
    context["email"] = user["email"]

    return flask.render_template("edit.html", **context)


@insta485.app.route('/accounts/password/')
def show_password_page():
    """Update Password Page."""
    if "username" in flask.session:
        logname = flask.session["username"]
    else:
        return flask.redirect("/accounts/login/")
    context = {"logname": logname}
    return flask.render_template("password.html", **context)


@insta485.app.route('/likes/', methods=["POST"])
def update_likes():
    """POST /likes/?target=URL."""
    LOGGER.debug("operation = %s", flask.request.form["operation"])
    LOGGER.debug("postid = %s", flask.request.form["postid"])
    url = flask.request.args.get("target")

    operation = flask.request.form["operation"]
    postid = int(flask.request.form["postid"])
    if "username" in flask.session:
        logname = flask.session["username"]
    else:
        return flask.redirect("/accounts/login/")

    # Connect to database
    connection = insta485.model.get_db()

    # Query database
    if operation == "unlike":
        cur = connection.execute(
            "DELETE FROM likes WHERE postid == ? and owner == ?",
            (postid, logname, )
        )
        if cur.rowcount == 0:
            flask.abort(409)
    else:
        cur = connection.execute(
            "SELECT * "
            "FROM likes "
            "WHERE postid == ? and owner == ? ",
            (postid, logname, )
        )
        num = cur.fetchall()
        if len(num) > 0:
            flask.abort(409)
        else:
            cur = connection.execute(
                "INSERT INTO likes(owner, postid) "
                "VALUES "
                "(?, ?);",
                (logname, postid)
            )

    return flask.redirect(url) if url else flask.redirect("/")


@insta485.app.route('/comments/', methods=["POST"])
def update_comments():
    """POST /comments/?target=URL."""
    LOGGER.debug("operation = %s", flask.request.form["operation"])
    url = flask.request.args.get("target")

    operation = flask.request.form["operation"]
    if "username" in flask.session:
        logname = flask.session["username"]
    else:
        return flask.redirect("/accounts/login/")

    # Connect to database
    connection = insta485.model.get_db()

    # Query database
    if operation == "create":
        text = flask.request.form["text"]
        postid = int(flask.request.form["postid"])
        if len(text) == 0:
            flask.abort(400)
        else:
            cur = connection.execute(
                "INSERT INTO comments(owner, postid, text) "
                "VALUES "
                "(?, ?, ?);",
                (logname, postid, text, )
            )
    else:
        commentid = int(flask.request.form["commentid"])
        cur = connection.execute(
            "SELECT owner "
            "FROM comments "
            "WHERE commentid = ?",
            (commentid, )
        )
        name = cur.fetchall()
        owner = name[0]["owner"]
        if owner != logname:
            flask.abort(403)
        cur = connection.execute(
            "DELETE FROM comments "
            "WHERE commentid = ?",
            (commentid, )
        )
        if cur.rowcount == 0:
            flask.abort(403)

    return flask.redirect(url) if url else flask.redirect("/")


@insta485.app.route('/posts/', methods=["POST"])
def update_post():
    """POST /posts/?target=URL."""
    LOGGER.debug("operation = %s", flask.request.form["operation"])
    url = flask.request.args.get("target")

    operation = flask.request.form["operation"]
    if "username" in flask.session:
        logname = flask.session["username"]
    else:
        return flask.redirect("/accounts/login/")

    # Connect to database
    connection = insta485.model.get_db()

    # Query database
    if operation == "create":
        fileobj = flask.request.files["file"]
        if not fileobj:
            flask.abort(400)
        else:
            filename = fileobj.filename
            stem = uuid.uuid4().hex
            suffix = pathlib.Path(filename).suffix.lower()
            uuid_basename = f"{stem}{suffix}"

            # Save to disk
            path = insta485.app.config["UPLOAD_FOLDER"]/uuid_basename
            fileobj.save(path)
            cur = connection.execute(
                "INSERT INTO posts(filename, owner) "
                "VALUES "
                "(?, ?);",
                (uuid_basename, logname, )
            )
    else:
        postid = int(flask.request.form["postid"])
        cur = connection.execute(
            "SELECT owner, filename FROM posts "
            "WHERE postid == ?",
            (postid, )
        )
        post = cur.fetchall()
        filename = post[0]["filename"]
        owner = post[0]["owner"]
        if owner != logname:
            flask.abort(403)
        (insta485.app.config["UPLOAD_FOLDER"]/filename).unlink()
        cur = connection.execute(
            "DELETE FROM posts "
            "WHERE postid == ?",
            (postid, )
        )
        if cur.rowcount == 0:
            flask.abort(403)

    if url:
        return flask.redirect(url)
    return flask.redirect("/users/" + logname + "/")


@insta485.app.route('/following/', methods=["POST"])
def update_following():
    """POST /following/?target=URL."""
    LOGGER.debug("operation = %s", flask.request.form["operation"])
    url = flask.request.args.get("target")

    operation = flask.request.form["operation"]
    if "username" in flask.session:
        logname = flask.session["username"]
    else:
        return flask.redirect("/accounts/login/")

    # Connect to database
    connection = insta485.model.get_db()

    # Query database
    if operation == "follow":
        username = flask.request.form["username"]
        cur = connection.execute(
            "SELECT * "
            "FROM following "
            "WHERE username1 == ? and username2 == ? ",
            (logname, username, )
        )
        data = cur.fetchall()
        if len(data) > 0:
            flask.abort(409)
        else:
            cur = connection.execute(
                "INSERT INTO following(username1, username2) "
                "VALUES "
                "(?, ?)",
                (logname, username, )
            )
    else:
        username = flask.request.form["username"]
        cur = connection.execute(
            "SELECT * "
            "FROM following "
            "WHERE username1 == ? and username2 == ? ",
            (logname, username, )
        )
        data = cur.fetchall()
        if len(data) == 0:
            flask.abort(409)
        else:
            cur = connection.execute(
                "DELETE FROM following "
                "WHERE username1 == ? and username2 == ? ",
                (logname, username, )
            )

    return flask.redirect(url) if url else flask.redirect("/")


@insta485.app.route('/accounts/logout/', methods=["POST"])
def account_logout():
    """POST /accounts/logout/."""
    flask.session.pop("username", None)
    return flask.redirect("/accounts/login/")


def login_account(username, password, url):
    """Login implementation."""
    if not username or not password:
        flask.abort(400)
    algorithm = 'sha512'
    hash_obj = hashlib.new(algorithm)

    # Connect to database
    connection = insta485.model.get_db()
    cur = connection.execute(
        "SELECT password "
        "FROM users "
        "WHERE username == ? ",
        (username, )
    )
    passwords = cur.fetchall()
    if len(passwords) == 0:
        flask.abort(403)
    correct_password = passwords[0]["password"].split('$')
    hashed_password = correct_password[-1]
    salt = correct_password[1]
    password_salted = salt + password
    hash_obj.update(password_salted.encode('utf-8'))
    password_hash = hash_obj.hexdigest()

    if hashed_password == password_hash:
        flask.session["username"] = username
        return flask.redirect(url) if url else flask.redirect("/")
    flask.abort(403)


def create_account(info, url):
    """Create account."""
    if (not info["fileobj"] or not info["password"] or not info["fullname"]
            or not info["username"] or not info["email"]):
        flask.abort(400)
    hash_obj = hashlib.new('sha512')

    # Connect to database
    connection = insta485.model.get_db()
    cur = connection.execute(
        "SELECT username "
        "FROM users "
        "WHERE username == ? ",
        (info["username"], )
    )
    data = cur.fetchall()
    if len(data) > 0:
        flask.abort(409)

    filename = info["fileobj"].filename
    stem = uuid.uuid4().hex
    suffix = pathlib.Path(filename).suffix.lower()
    filename = f"{stem}{suffix}"

    # Save to disk
    info["fileobj"].save(insta485.app.config["UPLOAD_FOLDER"]/filename)

    salt = uuid.uuid4().hex
    password = salt + info["password"]
    hash_obj.update(password.encode('utf-8'))
    password = hash_obj.hexdigest()
    password = "$".join(['sha512', salt, password])
    cur = connection.execute(
        "INSERT INTO users(username, fullname, email ,filename, password) "
        "VALUES "
        "(?, ?, ?, ?, ?)",
        (info["username"], info["fullname"], info["email"],
         filename, password, )
    )

    flask.session["username"] = info["username"]
    return flask.redirect(url)


def delete_account(url):
    """Delete account."""
    if "username" not in flask.session:
        flask.abort(403)
    logname = flask.session["username"]

    # Connect to database
    connection = insta485.model.get_db()
    cur = connection.execute(
        "SELECT filename "
        "FROM users "
        "WHERE username == ?",
        (logname, )
    )
    file = cur.fetchall()
    filename = file[0]["filename"]
    (insta485.app.config["UPLOAD_FOLDER"]/filename).unlink()
    cur = connection.execute(
        "SELECT filename "
        "FROM posts "
        "WHERE owner == ?",
        (logname, )
    )
    filenames = cur.fetchall()
    for file in filenames:
        (insta485.app.config["UPLOAD_FOLDER"]/file["filename"]).unlink()
    cur = connection.execute(
        "DELETE FROM users "
        "WHERE username == ?",
        (logname, )
    )
    flask.session.pop("username", None)
    return flask.redirect(url)


def edit_account(logname, fullname, email, fileobj, url):
    """Edit account."""
    # Connect to database
    connection = insta485.model.get_db()
    if not fullname or not email:
        flask.abort(400)
    if not fileobj:
        cur = connection.execute(
            "UPDATE users "
            "SET fullname = ?, email = ? "
            "WHERE username == ?",
            (fullname, email, logname, )
        )
    else:
        cur = connection.execute(
            "SELECT filename "
            "FROM users "
            "WHERE username == ?",
            (logname, )
        )
        file = cur.fetchall()
        filename_old = file[0]["filename"]
        (insta485.app.config["UPLOAD_FOLDER"]/filename_old).unlink()

        filename = fileobj.filename
        stem = uuid.uuid4().hex
        suffix = pathlib.Path(filename).suffix.lower()
        uuid_basename = f"{stem}{suffix}"

        # Save to disk
        path = insta485.app.config["UPLOAD_FOLDER"]/uuid_basename
        fileobj.save(path)
        cur = connection.execute(
            "UPDATE users "
            "SET fullname = ?, email = ?, filename = ? "
            "WHERE username == ?",
            (fullname, email, uuid_basename, logname, )
        )

    return flask.redirect(url)


def update_password(logname, password, new_password1, new_password2, url):
    """Update password."""
    if not password or not new_password1 or not new_password2:
        flask.abort(400)
    # Connect to database
    hash_obj = hashlib.new('sha512')
    connection = insta485.model.get_db()
    cur = connection.execute(
        "SELECT password "
        "FROM users "
        "WHERE username == ? ",
        (logname, )
    )
    passwords = cur.fetchall()
    if len(passwords) == 0:
        flask.abort(403)
    correct_password = passwords[0]["password"].split('$')
    hashed_password = correct_password[-1]
    salt = correct_password[1]
    password_salted = salt + password
    hash_obj.update(password_salted.encode('utf-8'))
    password_hash = hash_obj.hexdigest()

    if hashed_password != password_hash:
        flask.abort(403)
    if new_password1 != new_password2:
        flask.abort(401)

    salt = uuid.uuid4().hex
    hash_obj = hashlib.new('sha512')
    password_salted = salt + new_password1
    hash_obj.update(password_salted.encode('utf-8'))
    password_hash = hash_obj.hexdigest()
    password_db_string = "$".join(['sha512', salt, password_hash])
    cur = connection.execute(
        "UPDATE users "
        "SET password = ? "
        "WHERE username == ? ",
        (password_db_string, logname, )
    )
    return flask.redirect(url)


@insta485.app.route('/accounts/', methods=["POST"])
def update_account():
    """POST /accounts/?target=URL."""
    LOGGER.debug("operation = %s", flask.request.form["operation"])
    url = flask.request.args.get("target")

    operation = flask.request.form["operation"]

    if operation == "login":
        username = flask.request.form["username"]
        password = flask.request.form["password"]
        return login_account(username, password, url)
    if operation == "create":
        info = {}
        info["fileobj"] = flask.request.files["file"]
        info["password"] = flask.request.form["password"]
        info["fullname"] = flask.request.form["fullname"]
        info["username"] = flask.request.form["username"]
        info["email"] = flask.request.form["email"]
        return create_account(info, url)
    if operation == "delete":
        return delete_account(url)
    if operation == "edit_account":
        if "username" not in flask.session:
            flask.abort(403)
        logname = flask.session["username"]
        fullname = flask.request.form["fullname"]
        email = flask.request.form["email"]
        fileobj = flask.request.files["file"]
        return edit_account(logname, fullname, email,
                            fileobj, url)
    if "username" not in flask.session:
        flask.abort(403)
    logname = flask.session["username"]
    password = flask.request.form["password"]
    new_password1 = flask.request.form["new_password1"]
    new_password2 = flask.request.form["new_password2"]
    return update_password(logname, password, new_password1,
                           new_password2, url)


@insta485.app.route('/accounts/auth/')
def auth():
    """Account Authentication."""
    if "username" in flask.session:
        return "", 200
    flask.abort(403)
