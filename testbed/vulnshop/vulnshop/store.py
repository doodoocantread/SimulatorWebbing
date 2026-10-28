import hashlib
import secrets
import shutil
import sqlite3
import time
from pathlib import Path

from werkzeug.security import generate_password_hash

from . import config

QUERY_SECONDS = 2
DEFAULT_ADMIN_PASSWORD = "admin123"
DUMMY_HASH = generate_password_hash("placeholder-password", method="scrypt")

SCHEMA = """
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    email TEXT NOT NULL DEFAULT '',
    display_name TEXT NOT NULL DEFAULT ''
);
CREATE TABLE credentials (
    user_id INTEGER PRIMARY KEY REFERENCES users(id),
    username TEXT UNIQUE NOT NULL,
    pw_hash TEXT NOT NULL
);
CREATE TABLE products (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    price REAL NOT NULL,
    description TEXT NOT NULL
);
CREATE TABLE orders (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    product_id INTEGER NOT NULL REFERENCES products(id),
    quantity INTEGER NOT NULL,
    note TEXT NOT NULL DEFAULT ''
);
CREATE TABLE comments (
    id INTEGER PRIMARY KEY,
    product_id INTEGER NOT NULL REFERENCES products(id),
    author TEXT NOT NULL,
    body TEXT NOT NULL
);
CREATE TABLE comments_v2 (
    id INTEGER PRIMARY KEY,
    product_id INTEGER NOT NULL REFERENCES products(id),
    author TEXT NOT NULL,
    body TEXT NOT NULL
);
"""

# Fixed fake data (no real accounts). Non-admin passwords are long on purpose.
USERS = [
    (1, "admin", DEFAULT_ADMIN_PASSWORD, "admin", "admin@shop.test", "Shop Admin"),
    (2, "alice", "Qm7#vT2pLx9-Rw4zKd8sNc3b", "user", "alice@shop.test", "Alice"),
    (3, "bob", "Hy5!gF8nUe1-Zt6xJa0qMo2c", "user", "bob@shop.test", "Bob"),
    (4, "carol", "Wd3$kB9rPs4-Ev7yLn1hTu5j", "user", "carol@shop.test", "Carol"),
]
# Separate store for the hardened login; deliberately different from users.password.
CREDENTIALS = [
    (1, "admin", "Xr8&mC5wQa2-Fn9zBj4tVk7d"),
    (2, "alice", "Lp6@sD1eYh8-Gu3xOc5rWb9n"),
    (3, "bob", "Ta4%jN7vKi2-Mz6qHd0yEf8s"),
    (4, "carol", "Ub9^wG3oRl5-Ck1xZp7tJa4m"),
]
PRODUCTS = [
    (1, "Espresso Beans 1kg", 18.5, "Dark roast, whole beans."),
    (2, "Ceramic Mug", 7.0, "350 ml, dishwasher safe."),
    (3, "Pour-over Kit", 32.0, "Dripper, filter papers and server."),
    (4, "Tea Sampler", 14.25, "Six loose-leaf teas."),
    (5, "Milk Frother", 21.9, "Handheld, battery powered."),
    (6, "Grinder", 45.0, "Burr grinder, 15 settings."),
]
ORDERS = [
    (1, 2, 1, 2, "gift wrap"),
    (2, 3, 4, 1, ""),
    (3, 4, 6, 1, "leave at door"),
]
COMMENTS = [
    (1, 1, "alice", "Great aroma."),
    (2, 3, "bob", "Easy to use."),
]

SANDBOX_FILES = {
    "files/catalog.txt": "Catalog export (sample)\n1 Espresso Beans\n2 Ceramic Mug\n",
    "files/readme.txt": "Public downloads for the shop.\n",
    "files/prices.csv": "id,price\n1,18.5\n2,7.0\n",
    "secret/decoy-passwd.txt": "decoy:x:0:0:decoy:/nonexistent:/bin/false\n{flag_v09}\n",
    "etc/passwd": "root:x:0:0:decoy:/nonexistent:/bin/false\n"
                  "shop:x:1000:1000:decoy:/nonexistent:/bin/false\n{flag_v09}\n",
}


def flag(vuln_id):
    digest = hashlib.sha256(f"vulnshop-oracle-{vuln_id}".encode()).hexdigest()
    return f"FLAG{{{vuln_id}-{digest[:8]}}}"


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def connect_rw():
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def connect_ro():
    conn = sqlite3.connect(f"file:{config.DB_PATH}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    conn.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 1_000_000)
    deadline = time.monotonic() + QUERY_SECONDS
    conn.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 10_000)
    return conn


def _write_sandbox():
    if config.SANDBOX_DIR.exists():
        shutil.rmtree(config.SANDBOX_DIR)
    for rel, text in SANDBOX_FILES.items():
        target = config.SANDBOX_DIR / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text.format(flag_v09=flag("V09")))


def reset():
    """Rebuild every file under data/ from scratch."""
    config.DATA_DIR.mkdir(exist_ok=True)
    for path in (config.DB_PATH, config.ORACLE_PATH, config.KEY_PATH):
        path.unlink(missing_ok=True)
    config.KEY_PATH.write_bytes(secrets.token_bytes(32))
    config.ORACLE_PATH.touch()
    _write_sandbox()
    conn = sqlite3.connect(config.DB_PATH)
    try:
        conn.executescript(SCHEMA)
        conn.executemany(
            "INSERT INTO users VALUES (?,?,?,?,?,?)",
            [(i, u, hash_password(p), r, e, d) for i, u, p, r, e, d in USERS],
        )
        conn.executemany(
            "INSERT INTO credentials VALUES (?,?,?)",
            [(i, u, generate_password_hash(p, method="scrypt")) for i, u, p in CREDENTIALS],
        )
        conn.executemany("INSERT INTO products VALUES (?,?,?,?)", PRODUCTS)
        conn.executemany("INSERT INTO orders VALUES (?,?,?,?,?)", ORDERS)
        conn.executemany("INSERT INTO comments VALUES (?,?,?,?)", COMMENTS)
        conn.commit()
    finally:
        conn.close()


def ensure_ready():
    if not Path(config.DB_PATH).exists() or not Path(config.KEY_PATH).exists():
        reset()
