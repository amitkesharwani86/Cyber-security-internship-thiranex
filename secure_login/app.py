from flask import Flask, render_template, request, redirect, session, flash
from flask_bcrypt import Bcrypt
import sqlite3

app = Flask(__name__)
app.secret_key = "change_this_to_a_random_secret_key"

bcrypt = Bcrypt(app)

# ---------------------------
# Database Initialization
# ---------------------------

def init_db():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    """)

    conn.commit()
    conn.close()

init_db()

# ---------------------------
# Register
# ---------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"].strip()
        password = request.form["password"]

        if len(username) < 3:
            flash("Username too short")
            return redirect("/register")

        if len(password) < 8:
            flash("Password must be at least 8 characters")
            return redirect("/register")

        hashed = bcrypt.generate_password_hash(password).decode("utf-8")

        try:
            conn = sqlite3.connect("database.db")
            cursor = conn.cursor()

            cursor.execute(
                "INSERT INTO users(username,password) VALUES (?,?)",
                (username, hashed)
            )

            conn.commit()
            conn.close()

            flash("Registration successful")
            return redirect("/login")

        except sqlite3.IntegrityError:
            flash("Username already exists")

    return render_template("register.html")

# ---------------------------
# Login
# ---------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE username=?",
            (username,)
        )

        user = cursor.fetchone()
        conn.close()

        if user and bcrypt.check_password_hash(user[2], password):

            session["user"] = username
            return redirect("/dashboard")

        flash("Invalid Credentials")

    return render_template("login.html")

# ---------------------------
# Dashboard
# ---------------------------

@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect("/login")

    return render_template(
        "dashboard.html",
        user=session["user"]
    )

# ---------------------------
# Logout
# ---------------------------

@app.route("/logout")
def logout():

    session.pop("user", None)
    flash("Logged out successfully")

    return redirect("/login")

if __name__ == "__main__":
    app.run(debug=True)