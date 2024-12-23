from flask import Blueprint, request, jsonify, session, redirect
from . import query_db

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    if username is None or password is None:
        return jsonify({"error": "username and password parameter have to be provided"}), 400

    # Generate a secure salt
    salt = os.urandom(16)
    # Create a key using a KDF
    key = base64.urlsafe_b64encode(os.urandom(16))
    f = Fernet(key)
    # Store the salt and encrypted password in the database
    encrypted_password = f.encrypt(password.encode())
    query = "INSERT INTO user (username, password, salt) VALUES (?, ?, ?)"
    query_db(query, (username, encrypted_password, salt), commit=True)

    return jsonify({"success": True})



@bp.route("/login_and_redirect")
def login_and_redirect():
    username = request.args.get("username")
    password = request.args.get("password")
    url = request.args.get("url")
    if username is None or password is None or url is None:
        return (
            jsonify(
                {"error": "username, password, and url parameters have to be provided"}
            ),
            400,
        )

    query = "SELECT id, username, access_level FROM user WHERE username = ? AND password = ?"
    result = query_db(query, (username, password), True)
    if result is None:
        # vulnerability: Open Redirect
        return redirect(url)
    session["user_info"] = (result[0], result[1], result[2])
    return jsonify({"success": True})

