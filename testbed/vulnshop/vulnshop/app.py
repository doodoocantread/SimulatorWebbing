import http.client
import os
import posixpath
import re
import sqlite3
import traceback
from urllib.parse import urlsplit

from flask import Flask, Response, abort, g, jsonify, redirect, render_template, request
from markupsafe import Markup
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

from . import config, store, telemetry, tokens

VIRTUAL_ROOT = "/var/www/files"
REDIRECT_TARGETS = {"/", "/search", "/v2/search"}
LOOPBACK = config.ALLOWED_HOSTS
USERNAME_RE = re.compile(r"[A-Za-z0-9_]{3,32}")
PROFILE_UPDATES = {
    "display_name": "UPDATE users SET display_name=? WHERE id=?",
    "email": "UPDATE users SET email=? WHERE id=?",
    "role": "UPDATE users SET role=? WHERE id=?",
}


def create_app():
    config.check_host()
    store.ensure_ready()
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
    app.json.sort_keys = False

    def rw():
        if "rw" not in g:
            g.rw = store.connect_rw()
        return g.rw

    @app.teardown_appcontext
    def close_connections(_exc):
        conn = g.pop("rw", None)
        if conn is not None:
            conn.close()

    @app.before_request
    def require_loopback_host():
        if request.host.split(":")[0] not in config.ALLOWED_HOSTS:
            abort(400)

    @app.errorhandler(HTTPException)
    def http_error(exc):
        return jsonify(error=exc.name), exc.code

    @app.errorhandler(Exception)
    def unhandled(_exc):
        return jsonify(error="internal error"), 500

    def bearer():
        return request.headers.get("Authorization", "").removeprefix("Bearer ").strip()

    def legacy_user():
        payload = tokens.verify_legacy(bearer())
        if not payload or not isinstance(payload.get("sub"), str):
            abort(401)
        user = rw().execute("SELECT * FROM users WHERE username=?", (payload["sub"],)).fetchone()
        if user is None:
            abort(401)
        return user

    def strict_user():
        payload = tokens.verify_strict(bearer())
        if not payload or not isinstance(payload.get("uid"), int):
            abort(401)
        user = rw().execute("SELECT * FROM users WHERE id=?", (payload["uid"],)).fetchone()
        if user is None:
            abort(401)
        return user

    def params():
        data = request.get_json(silent=True)
        return data if isinstance(data, dict) else request.form

    def product_or_404(pid):
        row = rw().execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
        if row is None:
            abort(404)
        return row

    # ---- pages -------------------------------------------------------------

    @app.get("/")
    def index():
        products = rw().execute("SELECT id, name, price FROM products ORDER BY id").fetchall()
        return render_template("index.html", products=products)

    @app.get("/search")
    def search_page():
        q = request.args.get("q", "")
        like = "%" + q + "%"
        rows = rw().execute("SELECT id, name, price FROM products WHERE name LIKE ?", (like,)).fetchall()
        return render_template("search.html", q=Markup(q), rows=rows, prefix="")

    @app.get("/v2/search")
    def search_page_v2():
        q = request.args.get("q", "")
        like = "%" + q + "%"
        rows = rw().execute("SELECT id, name, price FROM products WHERE name LIKE ?", (like,)).fetchall()
        return render_template("search.html", q=q, rows=rows, prefix="/v2")

    @app.get("/product/<int:pid>")
    def product_page(pid):
        product = product_or_404(pid)
        rows = rw().execute("SELECT author, body FROM comments WHERE product_id=? ORDER BY id", (pid,)).fetchall()
        comments = [{"author": r["author"], "body": Markup(r["body"])} for r in rows]
        return render_template("product.html", product=product, comments=comments, api="/api")

    @app.get("/v2/product/<int:pid>")
    def product_page_v2(pid):
        product = product_or_404(pid)
        rows = rw().execute("SELECT author, body FROM comments_v2 WHERE product_id=? ORDER BY id", (pid,)).fetchall()
        return render_template("product.html", product=product, comments=rows, api="/api/v2")

    # ---- accounts ----------------------------------------------------------

    @app.post("/api/register")
    def register():
        data = params()
        username, password = str(data.get("username", "")), str(data.get("password", ""))
        if not USERNAME_RE.fullmatch(username) or len(password) < 8:
            return jsonify(error="invalid username or password"), 400
        conn = rw()
        if conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            return jsonify(error="username already taken"), 409
        cur = conn.execute(
            "INSERT INTO users (username, password, role, email, display_name) VALUES (?,?,?,?,?)",
            (username, store.hash_password(password), "user", str(data.get("email", ""))[:120], username),
        )
        conn.execute(
            "INSERT INTO credentials VALUES (?,?,?)",
            (cur.lastrowid, username, generate_password_hash(password, method="scrypt")),
        )
        conn.commit()
        return jsonify(id=cur.lastrowid, username=username), 201

    @app.post("/login")
    def login():
        data = params()
        username, password = str(data.get("username", "")), str(data.get("password", ""))
        query = "SELECT id, username, role FROM users WHERE username = '%s' AND password = '%s'" % (
            username,
            store.hash_password(password),
        )
        conn = store.connect_ro()
        try:
            row = conn.execute(query).fetchone()
        except sqlite3.Error:
            return jsonify(error="internal error"), 500
        finally:
            conn.close()
        if row is None:
            return jsonify(error="invalid credentials"), 401
        token = tokens.issue({"sub": row["username"], "uid": row["id"], "role": row["role"]})
        return jsonify(token=token, user={"id": row["id"], "username": row["username"], "role": row["role"]})

    @app.post("/v2/login")
    def login_v2():
        data = params()
        username, password = str(data.get("username", "")), str(data.get("password", ""))
        row = rw().execute("SELECT * FROM credentials WHERE username=?", (username,)).fetchone()
        stored = row["pw_hash"] if row else store.DUMMY_HASH
        if not check_password_hash(stored, password) or row is None:
            return jsonify(error="invalid credentials"), 401
        user = rw().execute("SELECT id, username, role FROM users WHERE id=?", (row["user_id"],)).fetchone()
        token = tokens.issue({"sub": user["username"], "uid": user["id"], "role": user["role"]})
        return jsonify(token=token, user=dict(user))

    @app.get("/api/profile")
    def profile_get():
        user = legacy_user()
        return jsonify(id=user["id"], username=user["username"], email=user["email"],
                       display_name=user["display_name"], role=user["role"])

    @app.put("/api/profile")
    def profile_update():
        user = legacy_user()
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify(error="expected a JSON object"), 400
        conn = rw()
        for field, statement in PROFILE_UPDATES.items():
            if field in data:
                conn.execute(statement, (str(data[field])[:120], user["id"]))
        conn.commit()
        return jsonify(updated=[f for f in PROFILE_UPDATES if f in data])

    # ---- catalogue ---------------------------------------------------------

    @app.get("/api/products")
    def product_list():
        rows = rw().execute("SELECT id, name, price, description FROM products ORDER BY id").fetchall()
        return jsonify([dict(r) for r in rows])

    @app.get("/api/products/<pid>")
    def product_detail(pid):
        try:
            row = rw().execute("SELECT id, name, price, description FROM products WHERE id=?", (int(pid),)).fetchone()
            if row is None:
                return jsonify(error="Not Found"), 404
            return jsonify(dict(row))
        except Exception:
            return Response(traceback.format_exc(), status=500, mimetype="text/plain")

    @app.get("/api/search")
    def search_api():
        q = request.args.get("q", "")
        query = "SELECT id, name, price FROM products WHERE name LIKE '%" + q + "%'"
        conn = store.connect_ro()
        try:
            rows = conn.execute(query).fetchall()
        except sqlite3.Error:
            return jsonify(error="internal error"), 500
        finally:
            conn.close()
        return jsonify([{"id": r[0], "name": r[1], "price": r[2]} for r in rows])

    @app.get("/api/v2/search")
    def search_api_v2():
        like = "%" + request.args.get("q", "") + "%"
        rows = rw().execute("SELECT id, name, price FROM products WHERE name LIKE ?", (like,)).fetchall()
        return jsonify([dict(r) for r in rows])

    # ---- comments ----------------------------------------------------------

    @app.post("/api/comments")
    def comment_create():
        user = legacy_user()
        data = params()
        body = str(data.get("body", ""))[:1000]
        pid = _int(data.get("product_id"))
        if pid is None or not body:
            return jsonify(error="product_id and body required"), 400
        product_or_404(pid)
        conn = rw()
        conn.execute("INSERT INTO comments (product_id, author, body) VALUES (?,?,?)", (pid, user["username"], body))
        conn.commit()
        return jsonify(ok=True), 201

    @app.post("/api/v2/comments")
    def comment_create_v2():
        user = strict_user()
        data = params()
        body = str(data.get("body", ""))[:1000]
        pid = _int(data.get("product_id"))
        if pid is None or not body:
            return jsonify(error="product_id and body required"), 400
        product_or_404(pid)
        conn = rw()
        conn.execute("INSERT INTO comments_v2 (product_id, author, body) VALUES (?,?,?)",
                     (pid, user["username"], body))
        conn.commit()
        return jsonify(ok=True), 201

    # ---- orders ------------------------------------------------------------

    @app.get("/api/orders")
    def order_list():
        user = legacy_user()
        rows = rw().execute("SELECT * FROM orders WHERE user_id=? ORDER BY id", (user["id"],)).fetchall()
        return jsonify([dict(r) for r in rows])

    @app.post("/api/orders")
    def order_create():
        user = legacy_user()
        data = params()
        pid, qty = _int(data.get("product_id")), _int(data.get("quantity"))
        if pid is None or qty is None or not 1 <= qty <= 100:
            return jsonify(error="product_id and quantity (1-100) required"), 400
        product_or_404(pid)
        conn = rw()
        cur = conn.execute(
            "INSERT INTO orders (user_id, product_id, quantity, note) VALUES (?,?,?,?)",
            (user["id"], pid, qty, str(data.get("note", ""))[:200]),
        )
        conn.commit()
        return jsonify(id=cur.lastrowid), 201

    @app.get("/api/orders/<int:oid>")
    def order_detail(oid):
        legacy_user()
        row = rw().execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone()
        if row is None:
            abort(404)
        return jsonify(dict(row))

    @app.get("/api/v2/orders/<int:oid>")
    def order_detail_v2(oid):
        user = strict_user()
        row = rw().execute("SELECT * FROM orders WHERE id=? AND user_id=?", (oid, user["id"])).fetchone()
        if row is None:
            abort(404)
        return jsonify(dict(row))

    # ---- admin -------------------------------------------------------------

    def user_rows():
        rows = rw().execute("SELECT id, username, role, email FROM users ORDER BY id").fetchall()
        return jsonify([dict(r) for r in rows])

    @app.get("/api/admin/users")
    def admin_users():
        legacy_user()
        return user_rows()

    @app.get("/api/v2/admin/users")
    def admin_users_v2():
        user = strict_user()
        if user["role"] != "admin":
            abort(403)
        return user_rows()

    # ---- files, fetch, redirect -------------------------------------------

    def sandbox_file(name, root=None):
        virtual = posixpath.normpath(posixpath.join(VIRTUAL_ROOT, name))
        relative = virtual[len("/var/www/"):] if virtual.startswith("/var/www/") else virtual.lstrip("/")
        try:
            real = os.path.realpath(config.SANDBOX_DIR / relative)
        except ValueError:
            abort(404)
        base = os.path.realpath(config.SANDBOX_DIR)
        confined = os.path.realpath(root) if root else base
        if not real.startswith(confined + os.sep) or not os.path.isfile(real):
            abort(404)
        return real

    def send_text(path):
        with open(path, "rb") as handle:
            return Response(handle.read(), mimetype="text/plain")

    @app.get("/download")
    def download():
        return send_text(sandbox_file(request.args.get("file", "")))

    @app.get("/v2/download")
    def download_v2():
        return send_text(sandbox_file(request.args.get("file", ""), root=config.SANDBOX_DIR / "files"))

    @app.get("/api/fetch")
    def fetch():
        try:
            parts = urlsplit(request.args.get("url", ""))
            port = parts.port or 80
        except ValueError:
            return jsonify(error="invalid url"), 400
        if parts.scheme != "http" or parts.hostname not in LOOPBACK:
            return jsonify(error="only loopback http urls are allowed"), 400
        target = (parts.path or "/") + ("?" + parts.query if parts.query else "")
        try:
            conn = http.client.HTTPConnection(config.BIND_ADDRESS, port, timeout=3)
            conn.request("GET", target, headers={"Host": f"{config.BIND_ADDRESS}:{port}"})
            reply = conn.getresponse()
            body = reply.read(65536).decode("utf-8", "replace")
            conn.close()
        except (OSError, http.client.HTTPException, ValueError):
            return jsonify(error="upstream request failed"), 502
        return jsonify(status=reply.status, body=body)

    @app.get("/redirect")
    def go():
        return redirect(request.args.get("next", "/"))

    @app.get("/v2/redirect")
    def go_v2():
        target = request.args.get("next", "/")
        parts = urlsplit(target)
        if parts.scheme or parts.netloc or "\\" in target or parts.path not in REDIRECT_TARGETS:
            target = "/"
        return redirect(target)

    telemetry.init_app(app)
    return app


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
