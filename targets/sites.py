"""The vulnerable lab: several small sites, each focused on a vuln class.

Each `make_*` factory returns a fresh Flask app bound to its own in-memory
state, so many targets can run at once (one port each). Ground truth for every
site lives in registry.py.

ALL targets are deliberately vulnerable practice apps and must stay on
localhost only.
"""
from __future__ import annotations

import html
import os
import secrets
import sqlite3
from pathlib import Path

from flask import Flask, abort, jsonify, redirect, request, session

from .common import fixes_reader, plant_canary, shell


def _add_security_headers(app, fixed):
    @app.after_request
    def _hdr(resp):
        if fixed("security_headers"):
            resp.headers["Content-Security-Policy"] = "default-src 'self'"
            resp.headers["X-Frame-Options"] = "DENY"
            resp.headers["X-Content-Type-Options"] = "nosniff"
            resp.headers["Referrer-Policy"] = "no-referrer"
        return resp


# =============================================================== 1) BANK : SQLi
def make_bank(fixes_path: Path) -> Flask:
    fixed = fixes_reader(fixes_path)
    app = Flask("bank")
    app.secret_key = secrets.token_hex(8)
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.executescript(
        "CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, balance REAL);"
        "INSERT INTO users VALUES(1,'admin','B4nk-Adm1n!','admin',100000),"
        "(2,'sara','sara2024','user',1500),(3,'omar','omar2024','user',300);"
    )
    _add_security_headers(app, fixed)
    nav = [("Login", "/login"), ("Accounts", "/accounts?holder=sara")]

    @app.route("/")
    def index():
        who = session.get("user")
        extra = f"<p>Signed in as {html.escape(who['username'])} ({who['role']}).</p>" if who else ""
        return shell("<p>MicroBank online banking.</p>" + extra, "MicroBank", nav)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return shell("<form method='post'><input name='username'>"
                         "<input name='password' type='password'><button>Login</button></form>", "MicroBank", nav)
        u, p = request.form.get("username", ""), request.form.get("password", "")
        try:
            if fixed("sqli_login"):
                row = db.execute("SELECT id,username,role FROM users WHERE username=? AND password=?",
                                 (u, p)).fetchone()
            else:
                row = db.execute(f"SELECT id,username,role FROM users WHERE username='{u}' AND password='{p}'"
                                 ).fetchone()
        except sqlite3.Error as e:
            return shell(f"<p>DB error: {html.escape(str(e))}</p>", "MicroBank", nav), 500
        if not row:
            return shell("<p>Invalid credentials</p>", "MicroBank", nav), 401
        session["user"] = {"id": row[0], "username": row[1], "role": row[2]}
        return redirect("/")

    @app.route("/accounts")
    def accounts():
        holder = request.args.get("holder", "")
        try:
            if fixed("sqli_search"):
                rows = db.execute("SELECT username,balance FROM users WHERE username LIKE ?",
                                  (f"%{holder}%",)).fetchall()
            else:
                rows = db.execute(f"SELECT username,balance FROM users WHERE username LIKE '%{holder}%'").fetchall()
        except sqlite3.Error as e:
            return shell(f"<p>DB error: {html.escape(str(e))}</p>", "MicroBank", nav), 500
        items = "".join(f"<li>{html.escape(u)}: balance hidden</li>" for u, _ in rows)
        return shell(f"<p>Accounts matching {html.escape(holder)}:</p><ul>{items}</ul>"
                     f"<p>{len(rows)} match(es)</p>", "MicroBank", nav)

    return app


# =============================================================== 2) BLOG : XSS
def make_blog(fixes_path: Path) -> Flask:
    fixed = fixes_reader(fixes_path)
    app = Flask("blog")
    _add_security_headers(app, fixed)
    nav = [("Search", "/search?q=hello"), ("Greet", "/hello?name=world")]

    @app.route("/")
    def index():
        return shell("<p>DevBlog - thoughts on code.</p>", "DevBlog", nav)

    @app.route("/search")
    def search():
        q = request.args.get("q", "")
        shown = html.escape(q) if fixed("xss_search") else q
        return shell(f"<p>You searched for: {shown}</p><p>No posts found.</p>", "DevBlog", nav)

    @app.route("/comment")
    def comment():
        text = request.args.get("text", "")
        shown = html.escape(text) if fixed("xss_comment") else text
        return shell(f"<h3>Preview</h3><div class='comment'>{shown}</div>", "DevBlog", nav)

    @app.route("/hello")  # decoy: safely escaped
    def hello():
        return shell(f"<p>Hello {html.escape(request.args.get('name', ''))}!</p>", "DevBlog", nav)

    return app


# =============================================================== 3) FILES : traversal + infoleak
def make_files(fixes_path: Path, base_dir: Path) -> Flask:
    fixed = fixes_reader(fixes_path)
    app = Flask("files")
    app.secret_key = "files-portal-secret-" + secrets.token_hex(4)
    files_dir = base_dir / "public"
    files_dir.mkdir(parents=True, exist_ok=True)
    (files_dir / "readme.txt").write_text("CloudFiles public readme\n", encoding="utf-8")
    (files_dir / "logo.txt").write_text("[logo]\n", encoding="utf-8")
    plant_canary(base_dir / "private")
    _add_security_headers(app, fixed)
    nav = [("Readme", "/download?file=readme.txt"), ("Docs", "/view?page=faq")]

    @app.route("/")
    def index():
        return shell("<p>CloudFiles document portal.</p>", "CloudFiles", nav)

    @app.route("/download")
    def download():
        name = request.args.get("file", "")
        if fixed("path_traversal"):
            target = (files_dir / name).resolve()
            if files_dir.resolve() not in target.parents:
                abort(403)
        else:
            target = Path(os.path.join(files_dir, name))
        if not target.is_file():
            abort(404)
        return target.read_text(encoding="utf-8", errors="replace"), 200, {"Content-Type": "text/plain"}

    @app.route("/view")  # decoy: whitelist
    def view():
        pages = {"faq": "Frequently asked questions", "help": "Help center"}
        return shell(f"<p>{html.escape(pages.get(request.args.get('page', ''), 'Unknown page'))}</p>",
                     "CloudFiles", nav)

    @app.route("/debug")
    def debug():
        if fixed("info_disclosure"):
            abort(404)
        return jsonify(debug=True, SECRET_KEY=app.secret_key, upload_dir=str(files_dir))

    @app.route("/robots.txt")
    def robots():
        return "User-agent: *\nDisallow: /debug\n", 200, {"Content-Type": "text/plain"}

    return app


# =============================================================== 4) SOCIAL : IDOR + open redirect
def make_social(fixes_path: Path) -> Flask:
    fixed = fixes_reader(fixes_path)
    app = Flask("social")
    app.secret_key = secrets.token_hex(8)
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.executescript(
        "CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, dob TEXT);"
        "INSERT INTO users VALUES(1,'admin','x','admin@chatly.local','1980-01-01'),"
        "(2,'lina','lina123','lina@chatly.local','1999-05-05'),"
        "(3,'kareem','kareem123','kareem@chatly.local','1997-03-03'),"
        "(4,'noor','noor123','noor@chatly.local','2001-09-09');"
    )
    _add_security_headers(app, fixed)
    nav = [("Login", "/login"), ("Logout to...", "/go?next=/")]

    @app.route("/")
    def index():
        who = session.get("user")
        extra = (f"<p>@{html.escape(who['username'])} - "
                 f"<a href='/api/profile/{who['id']}'>my profile</a></p>") if who else ""
        return shell("<p>Chatly social network.</p>" + extra, "Chatly", nav)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return shell("<form method='post'><input name='username'>"
                         "<input name='password' type='password'><button>Login</button></form>", "Chatly", nav)
        row = db.execute("SELECT id,username FROM users WHERE username=? AND password=?",
                         (request.form.get("username"), request.form.get("password"))).fetchone()
        if not row:
            return shell("<p>Invalid credentials</p>", "Chatly", nav), 401
        session["user"] = {"id": row[0], "username": row[1]}
        return redirect("/")

    @app.route("/api/profile/<int:uid>")
    def profile(uid):
        who = session.get("user")
        if not who:
            return jsonify(error="login required"), 401
        if fixed("idor") and who["id"] != uid and who["username"] != "admin":
            return jsonify(error="forbidden"), 403
        row = db.execute("SELECT id,username,email,dob FROM users WHERE id=?", (uid,)).fetchone()
        if not row:
            return jsonify(error="not found"), 404
        return jsonify(dict(zip(["id", "username", "email", "dob"], row)))

    @app.route("/go")
    def go():
        nxt = request.args.get("next", "/")
        if fixed("open_redirect") and not (nxt.startswith("/") and not nxt.startswith("//")):
            nxt = "/"
        return redirect(nxt)

    return app


# =============================================================== 5) CLEAN : no vulns (false-positive test)
def make_clean(fixes_path: Path) -> Flask:
    app = Flask("clean")

    @app.after_request
    def _hdr(resp):
        resp.headers["Content-Security-Policy"] = "default-src 'self'"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    nav = [("Search", "/search?q=hi"), ("Profile", "/profile?id=1")]
    names = {1: "Team", 2: "About"}

    @app.route("/")
    def index():
        return shell("<p>SecureCorp - we take security seriously.</p>", "SecureCorp", nav)

    @app.route("/search")
    def search():  # escaped + parameterised-equivalent (static data)
        q = request.args.get("q", "")
        return shell(f"<p>Results for {html.escape(q)}: none.</p>", "SecureCorp", nav)

    @app.route("/profile")
    def profile():  # whitelist lookup, no injection, no IDOR (public data only)
        try:
            pid = int(request.args.get("id", "0"))
        except ValueError:
            return shell("<p>Bad id</p>", "SecureCorp", nav), 400
        return shell(f"<p>{html.escape(names.get(pid, 'Unknown'))}</p>", "SecureCorp", nav)

    return app
