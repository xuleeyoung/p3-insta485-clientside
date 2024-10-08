"""REST API for posts."""
import hashlib
import flask
import insta485

def authentication(username, password): 
  if not username or not password:
    return False
  
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
    return False
  correct_password = passwords[0]["password"].split('$')
  hashed_password = correct_password[-1]
  salt = correct_password[1]
  password_salted = salt + password
  hash_obj.update(password_salted.encode('utf-8'))
  password_hash = hash_obj.hexdigest()

  if hashed_password != password_hash:
    return False
  return True

@insta485.app.route('/api/v1/posts/')
def get_post():
    """Return post on postid."""
    size = flask.request.args.get('size', default=10, type=int)
    postid_lte = flask.request.args.get('postid_lte', type=int)
    page = flask.request.args.get('page', default=0, type=int)
    
    if size <= 0 or page < 0:
      return flask.jsonify({'error': 'Bad Request', "status_code": 400}), 400
    
    if "username" not in flask.session:  
      if not flask.request.authorization:
        return flask.jsonify({'error': 'Forbidden', "status_code": 403}), 403
      username = flask.request.authorization['username']
      password = flask.request.authorization['password']
      if not authentication(username, password):
        return flask.jsonify({'error': 'Forbidden', "status_code": 403}), 403
    else:
      username = flask.session["username"]
    # Connect to database
    connection = insta485.model.get_db()

    # Query database
    context = {"next": ""}
    if postid_lte:
      cur = connection.execute(
          "SELECT posts.postid AS postid "
          "FROM posts "
          "WHERE (posts.owner in "
          "(SELECT username2 FROM following WHERE username1 == ?) "
          "or posts.owner == ? ) and posts.postid <= ? "
          "ORDER BY posts.postid DESC "
          "LIMIT ? OFFSET ? ",
          (username, username, postid_lte, size, page*size)
      )
      posts = cur.fetchall()
      context["results"] = posts
    else:
      cur = connection.execute(
          "SELECT posts.postid AS postid "
          "FROM posts "
          "WHERE (posts.owner in "
          "(SELECT username2 FROM following WHERE username1 == ?) "
          "or posts.owner == ? ) "
          "ORDER BY posts.postid DESC "
          "LIMIT ? OFFSET ? ",
          (username, username, size, page*size)
      )
      posts = cur.fetchall()
      context["results"] = posts
      postid_lte = context["results"][0]["postid"]
    
    for result in context["results"]:
      result["url"] = f"/api/v1/posts/{result["postid"]}/"
      
    context["url"] = "/api/v1/posts/" + flask.request.url.split("/")[-1]
    
    if len(context["results"]) < size:
      context["next"] = ""
    else:
      context["next"] = f"/api/v1/posts/?size={size}&page={page+1}&postid_lte={postid_lte}"
    return flask.jsonify(**context)
  

@insta485.app.route('/api/v1/posts/<int:postid_url_slug>/')
def get_one_post(postid_url_slug):
  """Return details for one post."""
  if "username" not in flask.session:  
    if not flask.request.authorization:
      return flask.jsonify({'error': 'Forbidden', "status_code": 403}), 403
    username = flask.request.authorization['username']
    password = flask.request.authorization['password']
    if not authentication(username, password):
      return flask.jsonify({'error': 'Forbidden', "status_code": 403}), 403
  else:
    username = flask.session["username"]
  # Connect to database
  connection = insta485.model.get_db()

  # Query database
  context = {"postid": postid_url_slug, 
             "url": f"/api/v1/posts/{postid_url_slug}/",
             "postShowUrl": f"/posts/{postid_url_slug}/"
            }
  
  cur = connection.execute(
      "SELECT posts.created, posts.filename AS imgUrl, posts.owner, users.filename AS ownerImgUrl "
      "FROM posts JOIN users on posts.owner == users.username "
      "WHERE posts.postid == ? ",
      (postid_url_slug, )
  )
  post_info = cur.fetchall()
  if len(post_info) == 0:
    return flask.jsonify({'error': 'Not Found', "status_code": 404}), 404
  context = context | post_info[0]
  context["imgUrl"] = f"/uploads/{context["imgUrl"]}"
  context["ownerImgUrl"] = f"/uploads/{context["ownerImgUrl"]}"
  context["ownerShowUrl"] = f"/users/{context["owner"]}/"
  
  cur = connection.execute(
      "SELECT commentid, owner, text "
      "FROM comments "
      "WHERE postid == ? "
      "ORDER BY commentid ASC ",
      (postid_url_slug, )
  )
  comments = cur.fetchall()
  context["comments"] = comments
  
  for comment in comments:
    comment["lognameOwnsThis"] = username == comment["owner"]
    comment["ownerShowUrl"] = f"/users/{comment["owner"]}/"
    comment["url"] = f"/api/v1/comments/{comment["commentid"]}/"
  
  context["comments_url"] = f"/api/v1/comments/?postid={postid_url_slug}"
  
  cur = connection.execute(
      "SELECT likeid, owner "
      "FROM likes "
      "WHERE postid == ? ",
      (postid_url_slug, )
  )
  likes = cur.fetchall()
  likeid = -1
  for like in likes:
    if like["owner"] == username:
      likeid = like["likeid"]
      break
  like_info = {
    "lognameLikesThis": likeid >= 0,
    "numLikes": len(likes),
  }
  like_info["url"] = f"/api/v1/likes/{likeid}/" if likeid >= 0 else None
  
  context["likes"] = like_info
  return flask.jsonify(**context)


@insta485.app.route('/api/v1/likes/', methods=["POST"])
def add_likes():
  postid = flask.request.args.get('postid', type=int)
  
  if "username" not in flask.session:  
    if not flask.request.authorization:
      return flask.jsonify({'error': 'Forbidden', "status_code": 403}), 403
    username = flask.request.authorization['username']
    password = flask.request.authorization['password']
    if not authentication(username, password):
      return flask.jsonify({'error': 'Forbidden', "status_code": 403}), 403
  else:
    username = flask.session["username"]
  # Connect to database
  connection = insta485.model.get_db()

  # Query database 
  cur = connection.execute(
    "SELECT MAX(postid) AS maxPostId "
    "FROM posts "
  )
  maxPostID = cur.fetchall()
  if postid > maxPostID[0]["maxPostId"] or postid < 0:
    return flask.jsonify({'error': 'Not Found', "status_code": 404}), 404
  cur = connection.execute(
      "SELECT likeid "
      "FROM likes "
      "WHERE owner == ? and postid == ? ",
      (username, postid, )
  )
  like = cur.fetchall()
  if len(like) > 0:
    like[0]["url"] = f"/api/v1/likes/{like[0]["likeid"]}/"
    return flask.jsonify(**like[0])
  
  cur = connection.execute(
      "INSERT INTO likes(owner, postid) "
      "VALUES "
      "(?, ?);",
      (username, postid)
  )
  cur = connection.execute(
      "SELECT likeid "
      "FROM likes "
      "WHERE owner == ? and postid == ? ",
      (username, postid, )
  )
  like = cur.fetchall()
  like[0]["url"] = f"/api/v1/likes/{like[0]["likeid"]}/"
  return flask.jsonify(**like[0]), 201
  

@insta485.app.route('/api/v1/likes/<int:likeid_url_slug>/', methods=["DELETE"])
def delete_likes(likeid_url_slug):
  if "username" not in flask.session:  
    if not flask.request.authorization:
      return flask.jsonify({'error': 'Forbidden', "status_code": 403}), 403
    username = flask.request.authorization['username']
    password = flask.request.authorization['password']
    if not authentication(username, password):
      return flask.jsonify({'error': 'Forbidden', "status_code": 403}), 403
  else:
    username = flask.session["username"]
  # Connect to database
  connection = insta485.model.get_db()

  # Query database 
  cur = connection.execute(
    "SELECT likeid, owner "
    "FROM likes "
    "WHERE likeid == ? ",
    (likeid_url_slug, )
  )
  like = cur.fetchall()
  if len(like) == 0:
    return flask.jsonify({'message': 'Not Found', "status_code": 404}), 404
  if like[0]["owner"] != username:
    return flask.jsonify({'message': 'Forbidden', "status_code": 403}), 403
  
  cur = connection.execute(
      "DELETE FROM likes WHERE likeid == ? ",
      (likeid_url_slug, )
  )
  return "", 204


@insta485.app.route('/api/v1/comments/', methods=["POST"])
def add_comments():
  postid = flask.request.args.get('postid', type=int)
  text = flask.request.get_json().get('text')
  
  if "username" not in flask.session:  
    if not flask.request.authorization:
      return flask.jsonify({'error': 'Forbidden', "status_code": 403}), 403
    username = flask.request.authorization['username']
    password = flask.request.authorization['password']
    if not authentication(username, password):
      return flask.jsonify({'error': 'Forbidden', "status_code": 403}), 403
  else:
    username = flask.session["username"]
  # Connect to database
  connection = insta485.model.get_db()

  # Query database 
  cur = connection.execute(
    "SELECT MAX(postid) AS maxPostId "
    "FROM posts "
  )
  maxPostId = cur.fetchall()
  if maxPostId[0]["maxPostId"] < postid:
    return flask.jsonify({'message': 'Not Found', "status_code": 404}), 404
  cur = connection.execute(
    "INSERT INTO comments(owner, postid, text) "
    "VALUES "
    "(?, ?, ?);",
    (username, postid, text, )
  )
  cur = connection.execute(
    "SELECT last_insert_rowid() AS maxCommentId "
    "FROM comments;"
  )
  maxCommentId = cur.fetchall()
  maxCommentId = maxCommentId[0]["maxCommentId"]
  cur = connection.execute(
    "SELECT owner, commentid, text "
    "FROM comments "
    "WHERE commentid == ? ",
    (maxCommentId, )
  )
  comment = cur.fetchall()
  context = comment[0]
  context["lognameOwnsThis"] = context["owner"] == username
  context["ownerShowUrl"] = f"/users/{context["owner"]}/"
  context["url"] = f"/api/v1/comments/{context["commentid"]}/"
  return flask.jsonify(**context), 201


@insta485.app.route('/api/v1/comments/<int:commentid_url_slug>/', methods=["DELETE"])
def delete_comments(commentid_url_slug):
  if "username" not in flask.session:  
    if not flask.request.authorization:
      return flask.jsonify({'error': 'Forbidden', "status_code": 403}), 403
    username = flask.request.authorization['username']
    password = flask.request.authorization['password']
    if not authentication(username, password):
      return flask.jsonify({'error': 'Forbidden', "status_code": 403}), 403
  else:
    username = flask.session["username"]
  # Connect to database
  connection = insta485.model.get_db()

  # Query database 
  cur = connection.execute(
    "SELECT commentid, owner "
    "FROM comments "
    "WHERE commentid == ? ",
    (commentid_url_slug, )
  )
  comment = cur.fetchall()
  if len(comment) == 0:
    return flask.jsonify({'message': 'Not Found', "status_code": 404}), 404
  if comment[0]["owner"] != username:
    return flask.jsonify({'message': 'Forbidden', "status_code": 403}), 403
  
  cur = connection.execute(
      "DELETE FROM comments WHERE commentid == ? ",
      (commentid_url_slug, )
  )
  return "", 204
