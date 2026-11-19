"""
VulnShop - an INTENTIONALLY VULNERABLE web app used as the ONLY target of CART.

!!  Never deploy this app on a public network. It binds to 127.0.0.1 only.  !!

Every vulnerability can be switched off ("patched") at runtime through
fixes.json, so CART can demonstrate:  find -> prove -> fix -> retest.

Known vulnerabilities (ground truth is in ground_truth.json):
  V1  SQL injection in /login           (authentication bypass)
  V2  SQL injection in /search          (boolean-based data leak)
  V3  Reflected XSS in /search
  V4  Path traversal in /download
  V5  IDOR in /api/users/<id>
  V6  Open redirect in /redirect
  V7  Information disclosure in /debug  (leaks SECRET_KEY)
  V8  Missing security headers
Decoys (look suspicious but are SAFE - used to measure false positives):
  /greet?name=   escapes its output
  /docs?page=    uses a whitelist
  /products?id=  uses a parameterised query
"""
import html
import json
import os
import secrets
import sqlite3
from pathlib import Path

from flask import Flask, abort, g, jsonify, redirect, request, session, make_response

BASE = Path(__file__).resolve().parent
FILES_DIR = BASE / "files"
PRIVATE_DIR = BASE / "private"
FIXES_FILE = Path(os.environ.get("VULNSHOP_FIXES", BASE / "fixes.json"))
DB_PATH = ":memory:"

app = Flask(__name__)
app.config["SECRET_KEY"] = "vulnshop-dev-secret-" + secrets.token_hex(4)


# --------------------------------------------------------------------------- setup
def _write_canary():
    """Plant a harmless canary file. CART proves path traversal by reading it."""
    PRIVATE_DIR.mkdir(exist_ok=True)
    FILES_DIR.mkdir(exist_ok=True)
    token = "CART-CANARY-" + secrets.token_hex(8)
    (PRIVATE_DIR / "canary.txt").write_text(token + "\n", encoding="utf-8")
    (FILES_DIR / "manual.txt").write_text("VulnShop user manual v1.0\n", encoding="utf-8")
    (FILES_DIR / "terms.txt").write_text("Terms of service: be nice.\n", encoding="utf-8")


def _make_db():
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.executescript(
        """
        CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT,
                           role TEXT, email TEXT, phone TEXT);
        INSERT INTO users VALUES
          (1,'admin','S3cure-Adm1n!','admin','admin@vulnshop.local','+000-0001'),
          (2,'alice','alice123','user','alice@vulnshop.local','+000-0002'),
          (3,'bob','bob123','user','bob@vulnshop.local','+000-0003');
        CREATE TABLE products(id INTEGER PRIMARY KEY, name TEXT, price REAL, hidden INTEGER);
        INSERT INTO products VALUES
          (1,'Laptop',999.0,0),(2,'Mouse',19.9,0),(3,'Keyboard',49.5,0),
          (4,'Internal prototype',0.0,1);
        """
    )
    return con


_write_canary()
DB = _make_db()


def fixes():
    """Read patch switches on every request so retests need no restart."""
    try:
        return json.loads(FIXES_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def fixed(name):
    return bool(fixes().get(name, False))


@app.after_request
def headers(resp):
    if fixed("security_headers"):
        resp.headers["Content-Security-Policy"] = "default-src 'self'"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


def page(body, title="VulnShop"):
    return (
        f"<html><head><title>{title}</title></head><body>"
        f"<h1>VulnShop</h1><nav><a href='/'>Home</a> | <a href='/login'>Login</a> | "
        f"<a href='/search?q=laptop'>Search</a> | <a href='/download?file=manual.txt'>Manual</a> | "
        f"<a href='/greet?name=guest'>Greet</a> | <a href='/docs?page=faq'>Docs</a> | "
        f"<a href='/products?id=1'>Product</a> | <a href='/redirect?next=/'>Back</a></nav>"
        f"<hr>{body}</body></html>"
    )


# --------------------------------------------------------------------------- routes
@app.route("/")
def index():
    who = session.get("user")
    extra = ""
    if who:
        extra = f"<p>Logged in as {html.escape(who['username'])}. " \
                f"<a href='/api/users/{who['id']}'>My profile</a> | <a href='/admin'>Admin</a></p>"
    return page("<p>Welcome to the shop.</p>" + extra)


@app.route("/robots.txt")
def robots():
    return "User-agent: *\nDisallow: /debug\nDisallow: /admin\n", 200, {"Content-Type": "text/plain"}


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return page(
            "<form method='post' action='/login'>"
            "<input name='username'><input name='password' type='password'>"
            "<button>Login</button></form>"
        )
    u = request.form.get("username", "")
    p = request.form.get("password", "")
    try:
        if fixed("sqli_login"):
            row = DB.execute(
                "SELECT id, username, role FROM users WHERE username=? AND password=?", (u, p)
            ).fetchone()
        else:
            # V1: string concatenation -> SQL injection (auth bypass)
            q = f"SELECT id, username, role FROM users WHERE username='{u}' AND password='{p}'"
            row = DB.execute(q).fetchone()
    except sqlite3.Error as e:
        return page(f"<p>Database error: {html.escape(str(e))}</p>"), 500
    if not row:
        return page("<p>Invalid credentials</p>"), 401
    session["user"] = {"id": row[0], "username": row[1], "role": row[2]}
    return redirect("/")


@app.route("/search")
def search():
    q = request.args.get("q", "")
    try:
        if fixed("sqli_search"):
            rows = DB.execute(
                "SELECT name, price FROM products WHERE hidden=0 AND name LIKE ?", (f"%{q}%",)
            ).fetchall()
        else:
            # V2: SQL injection
            rows = DB.execute(
                f"SELECT name, price FROM products WHERE hidden=0 AND name LIKE '%{q}%'"
            ).fetchall()
    except sqlite3.Error as e:
        return page(f"<p>Database error: {html.escape(str(e))}</p>"), 500
    shown = html.escape(q) if fixed("xss_search") else q  # V3: reflected XSS
    items = "".join(f"<li>{html.escape(n)} - ${p}</li>" for n, p in rows)
    return page(f"<p>Results for: {shown}</p><ul>{items}</ul><p>{len(rows)} result(s)</p>")


@app.route("/download")
def download():
    name = request.args.get("file", "")
    if fixed("path_traversal"):
        target = (FILES_DIR / name).resolve()
        if FILES_DIR.resolve() not in target.parents:
            abort(403)
    else:
        target = Path(os.path.join(FILES_DIR, name))  # V4: path traversal
    if not target.is_file():
        abort(404)
    return target.read_text(encoding="utf-8"), 200, {"Content-Type": "text/plain"}


@app.route("/api/users/<int:uid>")
def api_user(uid):
    who = session.get("user")
    if not who:
        return jsonify(error="login required"), 401
    if fixed("idor") and who["id"] != uid and who["role"] != "admin":
        return jsonify(error="forbidden"), 403  # V5 fixed: ownership check
    row = DB.execute("SELECT id, username, email, phone, role FROM users WHERE id=?", (uid,)).fetchone()
    if not row:
        return jsonify(error="not found"), 404
    return jsonify(dict(zip(["id", "username", "email", "phone", "role"], row)))


@app.route("/admin")
def admin():
    who = session.get("user")
    if not who or who["role"] != "admin":
        return page("<p>Admins only</p>"), 403
    users = DB.execute("SELECT username, email FROM users").fetchall()
    rows = "".join(f"<li>{html.escape(u)} &lt;{html.escape(e)}&gt;</li>" for u, e in users)
    return page(f"<h2>ADMIN PANEL</h2><ul>{rows}</ul>")


@app.route("/redirect")
def redir():
    nxt = request.args.get("next", "/")
    if fixed("open_redirect") and not (nxt.startswith("/") and not nxt.startswith("//")):
        nxt = "/"
    return redirect(nxt)  # V6: open redirect


@app.route("/debug")
def debug():
    if fixed("info_disclosure"):
        abort(404)
    # V7: leaks configuration
    return jsonify(debug=True, SECRET_KEY=app.config["SECRET_KEY"], db=DB_PATH,
                   python=os.sys.version.split()[0])


# ---- decoys: look interesting, but are safe -----------------------------------
@app.route("/greet")
def greet():
    return page(f"<p>Hello {html.escape(request.args.get('name', ''))}!</p>")


@app.route("/docs")
def docs():
    pages = {"faq": "Frequently asked questions", "shipping": "Shipping info"}
    return page(f"<p>{html.escape(pages.get(request.args.get('page', ''), 'Unknown page'))}</p>")


@app.route("/products")
def products():
    try:
        pid = int(request.args.get("id", "0"))
    except ValueError:
        return page("<p>Bad id</p>"), 400
    row = DB.execute("SELECT name, price FROM products WHERE id=? AND hidden=0", (pid,)).fetchone()
    return page(f"<p>{html.escape(row[0])} - ${row[1]}</p>" if row else "<p>Not found</p>")


def run(host="127.0.0.1", port=5000):
    if host not in ("127.0.0.1", "localhost"):
        raise SystemExit("VulnShop refuses to bind to anything except localhost.")
    app.run(host=host, port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    run(port=int(os.environ.get("VULNSHOP_PORT", 5000)))
