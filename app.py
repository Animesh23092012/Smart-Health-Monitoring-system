import os
import sys
import sqlite3
import secrets
from getpass import getpass
from datetime import datetime, timezone, date
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify, abort
)
from werkzeug.security import (
    check_password_hash,
    generate_password_hash
)

app = Flask(__name__)

# =========================================
# CONFIGURATION
# =========================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "database.db")

# Set FLASK_SECRET_KEY in Render environment settings.
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or (
    "local-development-" + secrets.token_hex(32)
)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("COOKIE_SECURE", "0") == "1"
)


# =========================================
# DATABASE
# =========================================

def get_db():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()

    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                password TEXT NOT NULL
            )
        """)

        columns = [
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(users)"
            ).fetchall()
        ]

        if "role" not in columns:
            conn.execute("""
                ALTER TABLE users
                ADD COLUMN role TEXT NOT NULL DEFAULT 'user'
            """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                date_of_birth TEXT NOT NULL DEFAULT '',
                relationship TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(owner_user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS sensor_readings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                heart_rate REAL,
                systolic REAL,
                diastolic REAL,
                sensor_status TEXT DEFAULT 'Demo',
                timestamp TEXT NOT NULL
            )
        """)

        reading_columns = [
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(sensor_readings)"
            ).fetchall()
        ]

        if "profile_id" not in reading_columns:
            conn.execute("""
                ALTER TABLE sensor_readings
                ADD COLUMN profile_id INTEGER
            """)

        users = conn.execute("""
            SELECT id, name, role FROM users
        """).fetchall()

        for user in users:
            if user["role"] == "user":
                exists = conn.execute("""
                    SELECT id FROM profiles
                    WHERE owner_user_id = ?
                    AND relationship = 'Self'
                    LIMIT 1
                """, (user["id"],)).fetchone()

                if not exists:
                    conn.execute("""
                        INSERT INTO profiles
                        (owner_user_id, name, date_of_birth,
                         relationship, created_at)
                        VALUES (?, ?, '', 'Self', ?)
                    """, (
                        user["id"],
                        user["name"],
                        datetime.now(timezone.utc).isoformat()
                    ))

        conn.commit()

    finally:
        conn.close()


# =========================================
# ACCOUNT AND PERMISSION HELPERS
# =========================================

def get_current_account():
    account_id = session.get("account_id")

    if not account_id:
        return None

    conn = get_db()

    try:
        return conn.execute("""
            SELECT id, user_id, name, role
            FROM users
            WHERE id = ?
        """, (account_id,)).fetchone()

    finally:
        conn.close()


def logged_in():
    return get_current_account() is not None


def admin_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        account = get_current_account()

        if not account:
            return redirect(url_for("login"))

        if account["role"] != "admin":
            abort(403)

        return function(*args, **kwargs)

    return wrapper


def user_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        account = get_current_account()

        if not account:
            return redirect(url_for("login"))

        if account["role"] != "user":
            abort(403)

        return function(*args, **kwargs)

    return wrapper


def current_profile():
    account = get_current_account()

    if not account or account["role"] != "user":
        return None

    profile_id = session.get("active_profile_id")

    if not profile_id:
        return None

    conn = get_db()

    try:
        return conn.execute("""
            SELECT * FROM profiles
            WHERE id = ? AND owner_user_id = ?
        """, (profile_id, account["id"])).fetchone()

    finally:
        conn.close()


def ensure_self_profile(account_id, name):
    conn = get_db()

    try:
        profile = conn.execute("""
            SELECT id FROM profiles
            WHERE owner_user_id = ?
            AND relationship = 'Self'
            LIMIT 1
        """, (account_id,)).fetchone()

        if not profile:
            conn.execute("""
                INSERT INTO profiles
                (owner_user_id, name, date_of_birth,
                 relationship, created_at)
                VALUES (?, ?, '', 'Self', ?)
            """, (
                account_id,
                name,
                datetime.now(timezone.utc).isoformat()
            ))

            conn.commit()

    finally:
        conn.close()


# =========================================
# ADMIN ACCOUNT CREATION
# =========================================

def create_account(name, user_id, password, role):
    if role not in ("user", "admin"):
        raise ValueError("Invalid account role.")

    if not name or not user_id:
        raise ValueError("Name and User ID are required.")

    if len(name) > 80 or len(user_id) > 40:
        raise ValueError("Name or User ID is too long.")

    if len(password) < 10:
        raise ValueError(
            "Password must contain at least 10 characters."
        )

    conn = get_db()

    try:
        cursor = conn.execute("""
            INSERT INTO users (user_id, name, password, role)
            VALUES (?, ?, ?, ?)
        """, (
            user_id,
            name,
            generate_password_hash(password),
            role
        ))

        account_id = cursor.lastrowid
        conn.commit()

    except sqlite3.IntegrityError:
        raise ValueError("This User ID already exists.")

    finally:
        conn.close()

    if role == "user":
        ensure_self_profile(account_id, name)

    return account_id


# =========================================
# AGE CALCULATION
# =========================================

def get_age_information(dob_text):
    if not dob_text:
        return "Not provided", "Age not provided"

    try:
        dob = date.fromisoformat(dob_text)
        today = date.today()

        if dob > today:
            return "Invalid date", "Unknown"

        years = today.year - dob.year

        if (today.month, today.day) < (dob.month, dob.day):
            years -= 1

        if years >= 100:
            return f"{years} years", "100+"

        if years >= 80:
            return f"{years} years", "Elderly adult"

        if years >= 60:
            return f"{years} years", "Older adult"

        if years >= 18:
            return f"{years} years", "Adult"

        if years >= 13:
            return f"{years} years", "Teenager"

        if years >= 1:
            return f"{years} years", "Child"

        days = (today - dob).days
        months = days // 30

        if months == 0:
            return f"{days} days", "Infant"

        return f"{months} months", "Infant"

    except ValueError:
        return "Invalid date", "Unknown"


# =========================================
# HOME
# =========================================

@app.route("/")
def home():
    account = get_current_account()

    if account:
        if account["role"] == "admin":
            return redirect(url_for("admin_dashboard"))

        return redirect(url_for("profiles"))

    return render_template("index.html")


# =========================================
# REGISTRATION
# =========================================

@app.route("/register", methods=["GET", "POST"])
def register():
    error = None

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        user_id = request.form.get("user_id", "").strip()
        password = request.form.get("password", "")

        try:
            account_id = create_account(
                name, user_id, password, "user"
            )

            session.clear()
            session["account_id"] = account_id

            return redirect(url_for("profiles"))

        except ValueError as exc:
            error = str(exc)

    return render_template("register.html", error=error)


# =========================================
# LOGIN
# =========================================

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        user_id = request.form.get("user_id", "").strip()
        password = request.form.get("password", "")
        login_type = request.form.get("login_type", "user")

        if login_type not in ("user", "admin"):
            error = "Please select a valid login type."

        else:
            conn = get_db()

            try:
                account = conn.execute("""
                    SELECT * FROM users
                    WHERE user_id = ?
                """, (user_id,)).fetchone()

            finally:
                conn.close()

            valid = (
                account
                and account["role"] == login_type
                and check_password_hash(
                    account["password"], password
                )
            )

            if valid:
                session.clear()
                session["account_id"] = account["id"]

                if account["role"] == "admin":
                    return redirect(url_for("admin_dashboard"))

                ensure_self_profile(
                    account["id"], account["name"]
                )

                return redirect(url_for("profiles"))

            error = "Invalid User ID, password, or login type."

    return render_template("login.html", error=error)


# =========================================
# ADMIN DASHBOARD
# =========================================

@app.route("/admin")
@admin_required
def admin_dashboard():
    conn = get_db()

    try:
        users = conn.execute("""
            SELECT id, name, user_id, role
            FROM users
            ORDER BY id DESC
        """).fetchall()

        total_users = conn.execute("""
            SELECT COUNT(*) AS total
            FROM users WHERE role = 'user'
        """).fetchone()["total"]

        total_admins = conn.execute("""
            SELECT COUNT(*) AS total
            FROM users WHERE role = 'admin'
        """).fetchone()["total"]

    finally:
        conn.close()

    return render_template(
        "admin_dashboard.html",
        users=users,
        total_users=total_users,
        total_admins=total_admins,
        account=get_current_account(),
        error=request.args.get("error"),
        success=request.args.get("success")
    )


# =========================================
# ADMIN CREATES USER OR ADMIN
# =========================================

@app.route("/admin/create-account", methods=["POST"])
@admin_required
def admin_create_account():
    token = request.form.get("csrf_token", "")

    if not token or token != session.get("admin_csrf_token"):
        abort(400)

    name = request.form.get("name", "").strip()
    user_id = request.form.get("user_id", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "user")

    try:
        create_account(name, user_id, password, role)

        return redirect(url_for(
            "admin_dashboard",
            success="Account created successfully."
        ))

    except ValueError as exc:
        return redirect(url_for(
            "admin_dashboard",
            error=str(exc)
        ))


@app.before_request
def prepare_admin_form_token():
    if (
        session.get("account_id")
        and not session.get("admin_csrf_token")
    ):
        session["admin_csrf_token"] = secrets.token_urlsafe(32)


# =========================================
# USER PROFILE SELECTION
# =========================================

@app.route("/profiles")
@user_required
def profiles():
    conn = get_db()

    try:
        rows = conn.execute("""
            SELECT * FROM profiles
            WHERE owner_user_id = ?
            ORDER BY id ASC
        """, (session["account_id"],)).fetchall()

    finally:
        conn.close()

    profile_list = []

    for profile in rows:
        item = dict(profile)

        item["age_label"], item["age_group"] = (
            get_age_information(item["date_of_birth"])
        )

        profile_list.append(item)

    return render_template(
        "profiles.html",
        profiles=profile_list
    )


# =========================================
# ADD FAMILY MEMBER
# =========================================

@app.route("/profiles/new", methods=["GET", "POST"])
@user_required
def add_profile():
    error = None

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        dob_text = request.form.get("date_of_birth", "").strip()
        relationship = request.form.get("relationship", "").strip()

        try:
            dob = date.fromisoformat(dob_text)

            if dob > date.today():
                raise ValueError

            if (date.today() - dob).days > 125 * 366:
                raise ValueError

            if not name or len(name) > 80:
                raise ValueError

            allowed = [
                "Child", "Parent", "Grandparent",
                "Spouse", "Other"
            ]

            if relationship not in allowed:
                raise ValueError

            conn = get_db()

            try:
                count = conn.execute("""
                    SELECT COUNT(*) AS total
                    FROM profiles WHERE owner_user_id = ?
                """, (session["account_id"],)).fetchone()["total"]

                if count >= 20:
                    error = "Maximum of 20 profiles reached."

                else:
                    conn.execute("""
                        INSERT INTO profiles
                        (owner_user_id, name, date_of_birth,
                         relationship, created_at)
                        VALUES (?, ?, ?, ?, ?)
                    """, (
                        session["account_id"],
                        name,
                        dob_text,
                        relationship,
                        datetime.now(timezone.utc).isoformat()
                    ))

                    conn.commit()

            finally:
                conn.close()

            if not error:
                return redirect(url_for("profiles"))

        except ValueError:
            error = "Please enter valid profile details."

    return render_template("add_profile.html", error=error)


# =========================================
# UPDATE DATE OF BIRTH
# =========================================

@app.route(
    "/profiles/<int:profile_id>/update-dob",
    methods=["POST"]
)
@user_required
def update_profile_dob(profile_id):
    dob_text = request.form.get("date_of_birth", "")

    try:
        dob = date.fromisoformat(dob_text)

        if dob > date.today():
            raise ValueError

        if (date.today() - dob).days > 125 * 366:
            raise ValueError

    except ValueError:
        return redirect(url_for("profiles"))

    conn = get_db()

    try:
        conn.execute("""
            UPDATE profiles
            SET date_of_birth = ?
            WHERE id = ? AND owner_user_id = ?
        """, (
            dob_text,
            profile_id,
            session["account_id"]
        ))

        conn.commit()

    finally:
        conn.close()

    return redirect(url_for("profiles"))


# =========================================
# SELECT PROFILE
# =========================================

@app.route(
    "/profiles/<int:profile_id>/select",
    methods=["POST"]
)
@user_required
def select_profile(profile_id):
    conn = get_db()

    try:
        profile = conn.execute("""
            SELECT id FROM profiles
            WHERE id = ? AND owner_user_id = ?
        """, (
            profile_id,
            session["account_id"]
        )).fetchone()

    finally:
        conn.close()

    if not profile:
        return redirect(url_for("profiles"))

    session["active_profile_id"] = profile["id"]

    return redirect(url_for("dashboard"))


# =========================================
# SWITCH PROFILE
# =========================================

@app.route("/switch-profile")
@user_required
def switch_profile():
    session.pop("active_profile_id", None)
    return redirect(url_for("profiles"))


# =========================================
# USER DASHBOARD
# =========================================

@app.route("/dashboard")
@user_required
def dashboard():
    profile = current_profile()

    if not profile:
        return redirect(url_for("profiles"))

    age_label, age_group = get_age_information(
        profile["date_of_birth"]
    )

    return render_template(
        "dashboard.html",
        name=profile["name"],
        age_label=age_label,
        age_group=age_group
    )


# =========================================
# LOGOUT
# =========================================

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# =========================================
# RECEIVE SENSOR DATA
# =========================================

@app.route("/api/sensor-data", methods=["POST"])
@user_required
def receive_sensor_data():
    profile = current_profile()

    if not profile:
        return jsonify({
            "success": False,
            "message": "Select a profile first."
        }), 400

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "message": "Invalid JSON data."
        }), 400

    def valid_number(value):
        if value is None or value == "":
            return None

        try:
            number = float(value)

            if not (-1000 < number < 1000):
                return "invalid"

            return number

        except (TypeError, ValueError):
            return "invalid"

    heart_rate = valid_number(data.get("heart_rate"))
    systolic = valid_number(data.get("systolic"))
    diastolic = valid_number(data.get("diastolic"))

    if "invalid" in (heart_rate, systolic, diastolic):
        return jsonify({
            "success": False,
            "message": "Invalid measurement."
        }), 400

    if all(value is None for value in (
        heart_rate, systolic, diastolic
    )):
        return jsonify({
            "success": False,
            "message": "No measurement provided."
        }), 400

    sensor_status = "Demo" if data.get("demo") else "Received"

    timestamp = datetime.now(
        timezone.utc
    ).isoformat(timespec="seconds")

    account = get_current_account()
    conn = get_db()

    try:
        conn.execute("""
            INSERT INTO sensor_readings
            (user_id, profile_id, heart_rate,
             systolic, diastolic, sensor_status, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            account["user_id"],
            profile["id"],
            heart_rate,
            systolic,
            diastolic,
            sensor_status,
            timestamp
        ))

        conn.commit()

    finally:
        conn.close()

    return jsonify({
        "success": True,
        "message": "Reading saved successfully.",
        "sensor_status": sensor_status
    })


# =========================================
# LATEST READING
# =========================================

@app.route("/api/latest-data")
@user_required
def latest_data():
    profile = current_profile()

    if not profile:
        return jsonify({"success": False}), 400

    conn = get_db()

    try:
        row = conn.execute("""
            SELECT heart_rate, systolic, diastolic,
                   sensor_status, timestamp
            FROM sensor_readings
            WHERE profile_id = ?
            ORDER BY id DESC
            LIMIT 1
        """, (profile["id"],)).fetchone()

    finally:
        conn.close()

    return jsonify({
        "success": True,
        "reading": dict(row) if row else None
    })


# =========================================
# READING HISTORY
# =========================================

@app.route("/api/reading-history")
@user_required
def reading_history():
    profile = current_profile()

    if not profile:
        return jsonify({"success": False}), 400

    conn = get_db()

    try:
        rows = conn.execute("""
            SELECT heart_rate, systolic, diastolic,
                   sensor_status, timestamp
            FROM sensor_readings
            WHERE profile_id = ?
            ORDER BY id DESC
            LIMIT 30
        """, (profile["id"],)).fetchall()

    finally:
        conn.close()

    return jsonify({
        "success": True,
        "readings": [dict(row) for row in rows]
    })


# =========================================
# ERROR PAGES
# =========================================

@app.errorhandler(403)
def forbidden(error):
    return (
        "<h1>Access denied</h1>"
        "<p>You do not have permission to open this page.</p>"
        '<p><a href="/">Return to home</a></p>',
        403
    )


# =========================================
# FIRST ADMIN SETUP
# =========================================

def create_first_admin():
    init_db()

    conn = get_db()

    try:
        existing = conn.execute("""
            SELECT COUNT(*) AS total
            FROM users WHERE role = 'admin'
        """).fetchone()["total"]

    finally:
        conn.close()

    if existing:
        print("An admin account already exists.")
        return

    print("\n--- Create First Admin Account ---")

    name = input("Admin name: ").strip()
    user_id = input("Admin User ID: ").strip()

    password = getpass(
        "Admin password (minimum 10 characters): "
    )

    confirm = getpass("Confirm password: ")

    if password != confirm:
        print("Passwords do not match.")
        return

    try:
        create_account(name, user_id, password, "admin")

        print("\nFirst admin account created successfully.")
        print("You can now start the website and use Admin Login.")

    except ValueError as exc:
        print(f"\nCould not create admin: {exc}")


# =========================================
# START APPLICATION
# =========================================

# Initialize tables when Gunicorn imports this application.
# Existing database records are preserved.
init_db()


if __name__ == "__main__":

    if "--create-admin" in sys.argv:
        create_first_admin()

    else:
        app.run(
            host="127.0.0.1",
            port=int(os.environ.get("PORT", 5000)),
            debug=False,
            use_reloader=False
        )