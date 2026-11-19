import hmac
import os
import re
import secrets
import sqlite3
from functools import wraps
from urllib.parse import unquote, urlparse

import click
from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


def get_secret_key():
    """Use a stable local key so form sessions survive app restarts."""
    configured_key = os.environ.get("SHOP_EASY_SECRET_KEY")
    if configured_key:
        return configured_key

    os.makedirs(app.instance_path, exist_ok=True)
    key_path = os.path.join(app.instance_path, ".secret_key")
    try:
        with open(key_path, "x", encoding="utf-8") as key_file:
            key_file.write(secrets.token_hex(32))
    except FileExistsError:
        pass

    with open(key_path, "r", encoding="utf-8") as key_file:
        return key_file.read().strip()


app = Flask(__name__)
app.config.update(
    # Set SHOP_EASY_SECRET_KEY in deployment; local development uses instance/.secret_key.
    SECRET_KEY=get_secret_key(),
    DATABASE=os.path.join(app.instance_path, "shopeasy.sqlite3"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SHOP_EASY_HTTPS_ONLY") == "1",
)


def init_db():
    """Create the app tables without replacing any existing records."""
    os.makedirs(app.instance_path, exist_ok=True)
    connection = sqlite3.connect(app.config["DATABASE"])
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_hash TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS admin_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS app_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                description TEXT NOT NULL,
                category TEXT NOT NULL,
                price INTEGER NOT NULL CHECK (price >= 0),
                rating TEXT NOT NULL DEFAULT '',
                badge TEXT NOT NULL DEFAULT '',
                image TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS cart_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                product_id INTEGER NOT NULL,
                quantity INTEGER NOT NULL CHECK (quantity BETWEEN 1 AND 99),
                UNIQUE (user_id, product_id),
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (product_id) REFERENCES products (id) ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                subtotal INTEGER NOT NULL CHECK (subtotal >= 0),
                delivery_charge INTEGER NOT NULL CHECK (delivery_charge >= 0),
                grand_total INTEGER NOT NULL CHECK (grand_total >= 0),
                status TEXT NOT NULL DEFAULT 'demo',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS order_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                order_id INTEGER NOT NULL,
                product_id INTEGER,
                product_name TEXT NOT NULL,
                unit_price INTEGER NOT NULL CHECK (unit_price >= 0),
                quantity INTEGER NOT NULL CHECK (quantity BETWEEN 1 AND 99),
                line_total INTEGER NOT NULL CHECK (line_total >= 0),
                FOREIGN KEY (order_id) REFERENCES orders (id) ON DELETE CASCADE,
                FOREIGN KEY (product_id) REFERENCES products (id) ON DELETE SET NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_orders_user_created ON orders (user_id, created_at)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_order_items_order ON order_items (order_id)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_cart_items_product ON cart_items (product_id)"
        )
        connection.commit()
    finally:
        connection.close()


def get_db():
    """Reuse one SQLite connection for the current request."""
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    database = g.pop("db", None)
    if database is not None:
        database.close()


def create_csrf_token():
    """Return a session-bound token used to protect account forms."""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_urlsafe(32)
    return session["_csrf_token"]


def valid_csrf_token():
    submitted_token = request.form.get("csrf_token", "")
    session_token = session.get("_csrf_token", "")
    return bool(session_token) and hmac.compare_digest(submitted_token, session_token)


def is_safe_redirect_target(target):
    """Allow only root-relative redirect targets on this same site."""
    if not target:
        return False
    decoded_target = unquote(target)
    parsed_target = urlparse(decoded_target)
    return (
        decoded_target.startswith("/")
        and not decoded_target.startswith("//")
        and "\\" not in decoded_target
        and not parsed_target.scheme
        and not parsed_target.netloc
    )


@app.context_processor
def inject_template_helpers():
    return {"csrf_token": create_csrf_token, "cart_count": get_cart_count}


def login_required(view):
    """Send visitors without an active login to the login page."""
    @wraps(view)
    def wrapped_view(**kwargs):
        if "user_id" not in session:
            flash("Please log in to view your account.", "info")
            return redirect(url_for("login", next=request.path))
        return view(**kwargs)

    return wrapped_view


def admin_required(view):
    """Require a valid admin account, independent of the customer login session."""
    @wraps(view)
    def wrapped_view(**kwargs):
        admin_id = session.get("admin_id")
        if admin_id is None:
            return redirect(url_for("admin_login", next=request.path))

        admin = get_db().execute(
            "SELECT id, name, username FROM admin_users WHERE id = ?",
            (admin_id,),
        ).fetchone()
        if admin is None:
            session.pop("admin_id", None)
            session.pop("admin_name", None)
            return redirect(url_for("admin_login"))
        return view(**kwargs)

    return wrapped_view


@app.cli.command("create-admin")
def create_admin():
    """Create the initial admin account once (the password is never echoed)."""
    database = get_db()
    database.execute("BEGIN IMMEDIATE")
    if database.execute("SELECT COUNT(*) FROM admin_users").fetchone()[0]:
        database.rollback()
        raise click.ClickException(
            "Admin setup has already been completed; no additional account was created."
        )

    name = click.prompt("Admin name").strip()
    username = click.prompt("Admin username").strip()
    password = click.prompt(
        "Admin password", hide_input=True, confirmation_prompt=True
    )
    if not name or len(name) > 100:
        database.rollback()
        raise click.ClickException("Name must contain 1 to 100 characters.")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,50}", username):
        database.rollback()
        raise click.ClickException(
            "Username must be 3-50 characters using letters, numbers, dots, dashes, or underscores."
        )
    if len(password) < 12 or len(password) > 128:
        database.rollback()
        raise click.ClickException("Password must contain 12 to 128 characters.")

    try:
        database.execute(
            "INSERT INTO admin_users (name, username, password_hash) VALUES (?, ?, ?)",
            (name, username, generate_password_hash(password)),
        )
        database.commit()
    except sqlite3.IntegrityError as error:
        database.rollback()
        raise click.ClickException("That admin username is already registered.") from error
    click.echo(f"Admin account '{username}' created.")


# Initialize the local database when the Flask app starts.
init_db()

# Homepage categories and sample products are kept here so they are easy to edit.
CATEGORIES = [
    {"name": "Electronics", "icon": "bi-headphones"},
    {"name": "Fashion", "icon": "bi-bag"},
    {"name": "Home & Kitchen", "icon": "bi-house-heart"},
    {"name": "Accessories", "icon": "bi-watch"},
]

PRODUCTS = [
    {
        "name": "Studio Wireless Headphones",
        "category": "Electronics",
        "description": "Comfortable over-ear sound with a rich, balanced wireless audio experience.",
        "price": 5499,
        "rating": "4.9",
        "badge": "Bestseller",
        "image": "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?auto=format&fit=crop&w=800&q=80",
    },
    {
        "name": "Everyday Canvas Tote",
        "category": "Fashion",
        "description": "A lightweight everyday tote with room for all your daily essentials.",
        "price": 1299,
        "rating": "4.8",
        "badge": "Loved",
        "image": "https://images.unsplash.com/photo-1590874103328-eac38a683ce7?auto=format&fit=crop&w=800&q=80",
    },
    {
        "name": "Minimal Ceramic Vase",
        "category": "Home & Kitchen",
        "description": "A simple ceramic accent that brings a calm, modern touch to any room.",
        "price": 1899,
        "rating": "4.7",
        "badge": "",
        "image": "https://images.unsplash.com/photo-1578500494198-246f612d3b3d?auto=format&fit=crop&w=800&q=80",
    },
    {
        "name": "Classic Leather Watch",
        "category": "Accessories",
        "description": "A timeless everyday watch with a clean dial and a comfortable leather strap.",
        "price": 3299,
        "rating": "4.9",
        "badge": "New",
        "image": "https://images.unsplash.com/photo-1523275335684-37898b6baf30?auto=format&fit=crop&w=800&q=80",
    },
    {
        "name": "Soft Knit Weekend Sweater",
        "category": "Fashion",
        "description": "A soft, cozy knit made for relaxed weekends and cooler evenings.",
        "price": 2499,
        "rating": "4.8",
        "badge": "",
        "image": "https://images.unsplash.com/photo-1620799140408-edc6dcb6d633?auto=format&fit=crop&w=800&q=80",
    },
    {
        "name": "Pour-Over Coffee Set",
        "category": "Home & Kitchen",
        "description": "A complete pour-over set for making a smooth cup of coffee at home.",
        "price": 2199,
        "rating": "4.6",
        "badge": "Staff pick",
        "image": "https://images.unsplash.com/photo-1495474472287-4d71bcdd2085?auto=format&fit=crop&w=800&q=80",
    },
    {
        "name": "Pocket Bluetooth Speaker",
        "category": "Electronics",
        "description": "Take your favorite playlists anywhere with this compact Bluetooth speaker.",
        "price": 2799,
        "rating": "4.7",
        "badge": "",
        "image": "https://images.unsplash.com/photo-1608043152269-423dbba4e7e1?auto=format&fit=crop&w=800&q=80",
    },
    {
        "name": "Everyday Sunglasses",
        "category": "Accessories",
        "description": "Lightweight sunglasses with a versatile shape for sunny days out.",
        "price": 1599,
        "rating": "4.8",
        "badge": "Trending",
        "image": "https://images.unsplash.com/photo-1511499767150-a48a237f0083?auto=format&fit=crop&w=800&q=80",
    },
]

# More sample products make the dedicated listing page useful for browsing.
PRODUCTS.extend([
    {
        "name": "Compact Digital Camera",
        "category": "Electronics",
        "description": "Capture everyday moments with a pocket-friendly digital camera.",
        "price": 8999,
        "rating": "4.6",
        "badge": "Popular",
        "image": "https://images.unsplash.com/photo-1516035069371-29a1b244cc32?auto=format&fit=crop&w=800&q=80",
    },
    {
        "name": "Classic Cotton Shirt",
        "category": "Fashion",
        "description": "An easy-to-style cotton shirt designed for everyday comfort.",
        "price": 1799,
        "rating": "4.7",
        "badge": "",
        "image": "https://images.unsplash.com/photo-1596755094514-f87e34085b2c?auto=format&fit=crop&w=800&q=80",
    },
    {
        "name": "Stoneware Dinner Set",
        "category": "Home & Kitchen",
        "description": "A durable, neutral-toned dinner set for relaxed meals at home.",
        "price": 3599,
        "rating": "4.8",
        "badge": "New",
        "image": "https://images.unsplash.com/photo-1603199506016-b9a594b593c0?auto=format&fit=crop&w=800&q=80",
    },
    {
        "name": "Everyday Leather Wallet",
        "category": "Accessories",
        "description": "A slim wallet with thoughtful space for cards and everyday essentials.",
        "price": 1199,
        "rating": "4.5",
        "badge": "",
        "image": "https://images.unsplash.com/photo-1627123424574-724758594e93?auto=format&fit=crop&w=800&q=80",
    },
])


def load_products_from_db():
    """Seed an empty catalogue once, then use SQLite as the product source."""
    connection = sqlite3.connect(app.config["DATABASE"])
    connection.row_factory = sqlite3.Row
    try:
        seeded = connection.execute(
            "SELECT value FROM app_metadata WHERE key = 'sample_products_seeded'"
        ).fetchone()
        count = connection.execute("SELECT COUNT(*) FROM products").fetchone()[0]
        if not seeded and count == 0:
            connection.executemany(
                """
                INSERT INTO products
                    (name, description, category, price, rating, badge, image)
                VALUES
                    (:name, :description, :category, :price, :rating, :badge, :image)
                """,
                PRODUCTS,
            )
        if not seeded:
            connection.execute(
                "INSERT INTO app_metadata (key, value) VALUES ('sample_products_seeded', '1')"
            )
        connection.commit()
        rows = connection.execute(
            """
            SELECT id, name, description, category, price, rating, badge, image
            FROM products
            ORDER BY id
            """
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


# Seed sample products once. UNIQUE names and INSERT OR IGNORE prevent duplicates.
PRODUCTS = load_products_from_db()


def refresh_products():
    """Refresh the in-memory product list after an admin catalogue change."""
    global PRODUCTS
    connection = sqlite3.connect(app.config["DATABASE"])
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            """
            SELECT id, name, description, category, price, rating, badge, image
            FROM products
            ORDER BY id
            """
        ).fetchall()
        PRODUCTS = [dict(row) for row in rows]
    finally:
        connection.close()

# Delivery is free for orders of ₹1,999 or more.
DELIVERY_CHARGE = 99
FREE_DELIVERY_THRESHOLD = 1999


def get_cart():
    """Read the signed-in user's database cart or a guest's session cart."""
    user_id = session.get("user_id")
    if user_id is not None:
        rows = get_db().execute(
            """
            SELECT products.name, cart_items.quantity
            FROM cart_items
            JOIN products ON products.id = cart_items.product_id
            WHERE cart_items.user_id = ?
            ORDER BY cart_items.id
            """,
            (user_id,),
        ).fetchall()
        return {row["name"]: row["quantity"] for row in rows}

    cart = session.get("cart", {})
    if not isinstance(cart, dict):
        return {}

    product_names = {product["name"] for product in PRODUCTS}
    valid_cart = {}
    for product_name, quantity in cart.items():
        if (
            product_name in product_names
            and isinstance(quantity, int)
            and not isinstance(quantity, bool)
            and 1 <= quantity <= 99
        ):
            valid_cart[product_name] = quantity
    return valid_cart


def save_cart(cart):
    """Persist signed-in cart changes, or keep guest carts in the session."""
    user_id = session.get("user_id")
    database = get_db() if user_id is not None else None
    if database is None:
        session["cart"] = cart
        return

    database.execute("DELETE FROM cart_items WHERE user_id = ?", (user_id,))
    for product_name, quantity in cart.items():
        product = next((item for item in PRODUCTS if item["name"] == product_name), None)
        if product is not None and 1 <= quantity <= 99:
            database.execute(
                """
                INSERT INTO cart_items (user_id, product_id, quantity)
                VALUES (?, ?, ?)
                """,
                (user_id, product["id"], quantity),
            )
    database.commit()


def move_guest_cart_to_user(user_id, guest_cart):
    """Merge a visitor's current session cart into their persistent user cart."""
    for product_name, guest_quantity in guest_cart.items():
        product = next((item for item in PRODUCTS if item["name"] == product_name), None)
        if product is None:
            continue
        row = get_db().execute(
            "SELECT quantity FROM cart_items WHERE user_id = ? AND product_id = ?",
            (user_id, product["id"]),
        ).fetchone()
        if row:
            quantity = min(row["quantity"] + guest_quantity, 99)
            get_db().execute(
                "UPDATE cart_items SET quantity = ? WHERE user_id = ? AND product_id = ?",
                (quantity, user_id, product["id"]),
            )
        else:
            get_db().execute(
                "INSERT INTO cart_items (user_id, product_id, quantity) VALUES (?, ?, ?)",
                (user_id, product["id"], guest_quantity),
            )
    get_db().commit()


def get_cart_count():
    """Count all units in the cart for the navbar badge."""
    return sum(get_cart().values())


def get_cart_summary():
    """Build cart rows and totals from trusted product data."""
    cart = get_cart()
    items = []
    subtotal = 0

    for product in PRODUCTS:
        quantity = cart.get(product["name"], 0)
        if not quantity:
            continue
        line_total = product["price"] * quantity
        subtotal += line_total
        items.append({
            "product": product,
            "quantity": quantity,
            "line_total": line_total,
        })

    delivery_charge = 0 if subtotal == 0 or subtotal >= FREE_DELIVERY_THRESHOLD else DELIVERY_CHARGE
    return {
        "items": items,
        "subtotal": subtotal,
        "delivery_charge": delivery_charge,
        "grand_total": subtotal + delivery_charge,
    }


@app.route("/")
def home():
    return render_template("index.html", categories=CATEGORIES, products=PRODUCTS)


@app.route("/products")
def products_page():
    # Apply search and category filters on the server so links and refreshes work.
    search_query = request.args.get("q", "").strip()
    selected_category = request.args.get("category", "").strip()
    filtered_products = PRODUCTS

    if search_query:
        filtered_products = [
            product for product in filtered_products
            if search_query.casefold() in product["name"].casefold()
        ]

    if selected_category in [category["name"] for category in CATEGORIES]:
        filtered_products = [
            product for product in filtered_products
            if product["category"] == selected_category
        ]
    else:
        selected_category = ""

    return render_template(
        "products.html",
        categories=CATEGORIES,
        products=filtered_products,
        search_query=search_query,
        selected_category=selected_category,
    )


@app.route("/cart")
def cart():
    return render_template("cart.html", **get_cart_summary())


@app.route("/cart/add", methods=["POST"])
def add_to_cart():
    if not valid_csrf_token():
        flash("Your form expired. Please try adding the item again.", "danger")
        return redirect(url_for("cart"))

    product_name = request.form.get("product_name", "")
    product = next((item for item in PRODUCTS if item["name"] == product_name), None)
    if product is None:
        flash("That product could not be found.", "danger")
        return redirect(url_for("products_page"))

    cart_items = get_cart()
    if cart_items.get(product_name, 0) >= 99:
        flash("A maximum of 99 of each product can be added.", "warning")
        return redirect(url_for("cart"))
    cart_items[product_name] = cart_items.get(product_name, 0) + 1
    save_cart(cart_items)
    flash(f"{product_name} added to your cart.", "success")
    return redirect(url_for("cart"))


@app.route("/cart/update", methods=["POST"])
def update_cart_item():
    if not valid_csrf_token():
        flash("Your form expired. Please try again.", "danger")
        return redirect(url_for("cart"))

    product_name = request.form.get("product_name", "")
    action = request.form.get("action", "")
    cart_items = get_cart()

    if product_name not in cart_items or action not in {"increase", "decrease"}:
        flash("That cart update could not be applied.", "warning")
        return redirect(url_for("cart"))

    if action == "increase":
        if cart_items[product_name] >= 99:
            flash("A maximum of 99 of each product can be added.", "info")
        else:
            cart_items[product_name] += 1
    elif cart_items[product_name] <= 1:
        del cart_items[product_name]
    else:
        cart_items[product_name] -= 1

    save_cart(cart_items)
    return redirect(url_for("cart"))


@app.route("/cart/remove", methods=["POST"])
def remove_from_cart():
    if not valid_csrf_token():
        flash("Your form expired. Please try again.", "danger")
        return redirect(url_for("cart"))

    product_name = request.form.get("product_name", "")
    cart_items = get_cart()
    if product_name in cart_items:
        del cart_items[product_name]
        save_cart(cart_items)
        flash("Item removed from your cart.", "info")
    else:
        flash("That item is not in your cart.", "warning")
    return redirect(url_for("cart"))


@app.route("/checkout", methods=["GET", "POST"])
def checkout():
    if request.method == "POST":
        if not valid_csrf_token():
            flash("Your form expired. Please try again.", "danger")
            return redirect(url_for("cart"))

        summary = get_cart_summary()
        if not summary["items"]:
            flash("Your cart is empty. Add products before checking out.", "info")
            return redirect(url_for("cart"))

        database = get_db()
        database.execute("BEGIN")
        cursor = database.execute(
            """
            INSERT INTO orders (user_id, subtotal, delivery_charge, grand_total)
            VALUES (?, ?, ?, ?)
            """,
            (
                session.get("user_id"),
                summary["subtotal"],
                summary["delivery_charge"],
                summary["grand_total"],
            ),
        )
        order_id = cursor.lastrowid
        for item in summary["items"]:
            database.execute(
                """
                INSERT INTO order_items
                    (order_id, product_id, product_name, unit_price, quantity, line_total)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    order_id,
                    item["product"]["id"],
                    item["product"]["name"],
                    item["product"]["price"],
                    item["quantity"],
                    item["line_total"],
                ),
            )
        if session.get("user_id") is not None:
            database.execute(
                "DELETE FROM cart_items WHERE user_id = ?",
                (session["user_id"],),
            )
        database.commit()
        if session.get("user_id") is None:
            session["cart"] = {}
        session["last_order_id"] = order_id
        flash("Your demo order was saved. No payment was taken.", "success")
        return redirect(url_for("checkout"))

    return render_template(
        "checkout.html",
        last_order_id=session.pop("last_order_id", None),
        **get_cart_summary(),
    )


ADMIN_ORDER_STATUSES = ("demo", "processing", "shipped", "delivered", "cancelled")


def validate_admin_product_form():
    """Validate product fields shared by the admin create and edit forms."""
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    category = request.form.get("category", "").strip()
    price_text = request.form.get("price", "").strip()
    rating = request.form.get("rating", "").strip()
    badge = request.form.get("badge", "").strip()
    image = request.form.get("image", "").strip()

    if not name or len(name) > 150:
        flash("Product name is required and must be 150 characters or fewer.", "danger")
        return None
    if not description or len(description) > 2000:
        flash("Description is required and must be 2,000 characters or fewer.", "danger")
        return None
    if category not in {item["name"] for item in CATEGORIES}:
        flash("Choose one of the listed product categories.", "danger")
        return None
    try:
        price = int(price_text)
    except ValueError:
        flash("Enter the price as a whole number of rupees.", "danger")
        return None
    if price < 0 or price > 10000000:
        flash("Price must be between ₹0 and ₹10,000,000.", "danger")
        return None
    if rating:
        try:
            numeric_rating = float(rating)
        except ValueError:
            numeric_rating = -1
        if not 0 <= numeric_rating <= 5:
            flash("Rating must be a number from 0 to 5.", "danger")
            return None
    if len(badge) > 40:
        flash("Badge must be 40 characters or fewer.", "danger")
        return None
    parsed_image = urlparse(image)
    if not (
        image.startswith("/static/")
        or (parsed_image.scheme in {"http", "https"} and parsed_image.netloc)
    ):
        flash("Use an http(s) image URL or a path inside /static/.", "danger")
        return None

    return {
        "name": name,
        "description": description,
        "category": category,
        "price": price,
        "rating": rating,
        "badge": badge,
        "image": image,
    }


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        if not valid_csrf_token():
            flash("Your form expired. Please try again.", "danger")
            return redirect(url_for("admin_login"))
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        admin = get_db().execute(
            "SELECT id, name, username, password_hash FROM admin_users WHERE username = ?",
            (username,),
        ).fetchone()
        if admin is None or not check_password_hash(admin["password_hash"], password):
            flash("Admin username or password is incorrect.", "danger")
        else:
            guest_cart = session.get("cart") if "user_id" not in session else None
            session.clear()
            session["admin_id"] = admin["id"]
            session["admin_name"] = admin["name"]
            if guest_cart:
                session["cart"] = guest_cart
            next_page = request.args.get("next", "")
            if is_safe_redirect_target(next_page):
                return redirect(next_page)
            return redirect(url_for("admin_dashboard"))
    return render_template("admin/login.html")


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    if not valid_csrf_token():
        flash("Your form expired. Please sign in again.", "danger")
        guest_cart = session.get("cart")
        session.clear()
        if guest_cart:
            session["cart"] = guest_cart
        return redirect(url_for("admin_login"))
    guest_cart = session.get("cart")
    session.clear()
    if guest_cart:
        session["cart"] = guest_cart
    return redirect(url_for("admin_login"))


@app.route("/admin")
@admin_required
def admin_dashboard():
    database = get_db()
    totals = {
        "users": database.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "products": database.execute("SELECT COUNT(*) FROM products").fetchone()[0],
        "orders": database.execute("SELECT COUNT(*) FROM orders").fetchone()[0],
        "sales": database.execute(
            "SELECT COALESCE(SUM(grand_total), 0) FROM orders WHERE status != 'cancelled'"
        ).fetchone()[0],
    }
    recent_orders = database.execute(
        """
        SELECT orders.id, orders.grand_total, orders.status, orders.created_at,
               users.name AS customer_name
        FROM orders
        LEFT JOIN users ON users.id = orders.user_id
        ORDER BY orders.id DESC
        LIMIT 5
        """
    ).fetchall()
    return render_template("admin/dashboard.html", totals=totals, orders=recent_orders)


@app.route("/admin/products")
@admin_required
def admin_products():
    products = get_db().execute(
        """
        SELECT id, name, category, price, image
        FROM products
        ORDER BY id DESC
        """
    ).fetchall()
    return render_template("admin/products.html", products=products)


@app.route("/admin/products/new", methods=["GET", "POST"])
@admin_required
def admin_product_create():
    product = {}
    if request.method == "POST":
        if not valid_csrf_token():
            flash("Your form expired. Please try again.", "danger")
            return redirect(url_for("admin_product_create"))
        product = request.form
        product_data = validate_admin_product_form()
        if product_data is not None:
            try:
                database = get_db()
                database.execute(
                    """
                    INSERT INTO products
                        (name, description, category, price, rating, badge, image)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        product_data["name"],
                        product_data["description"],
                        product_data["category"],
                        product_data["price"],
                        product_data["rating"],
                        product_data["badge"],
                        product_data["image"],
                    ),
                )
                database.commit()
            except sqlite3.IntegrityError:
                flash("A product with that name already exists.", "danger")
            else:
                refresh_products()
                flash("Product added successfully.", "success")
                return redirect(url_for("admin_products"))
    return render_template(
        "admin/product_form.html",
        product=product,
        categories=CATEGORIES,
        page_title="Add product",
    )


@app.route("/admin/products/<int:product_id>/edit", methods=["GET", "POST"])
@admin_required
def admin_product_edit(product_id):
    database = get_db()
    product_row = database.execute(
        "SELECT * FROM products WHERE id = ?", (product_id,)
    ).fetchone()
    if product_row is None:
        return "Product not found", 404
    product = dict(product_row)

    if request.method == "POST":
        if not valid_csrf_token():
            flash("Your form expired. Please try again.", "danger")
            return redirect(url_for("admin_product_edit", product_id=product_id))
        product = request.form
        product_data = validate_admin_product_form()
        if product_data is not None:
            try:
                database.execute(
                    """
                    UPDATE products
                    SET name = ?, description = ?, category = ?, price = ?,
                        rating = ?, badge = ?, image = ?
                    WHERE id = ?
                    """,
                    (*product_data.values(), product_id),
                )
                database.commit()
            except sqlite3.IntegrityError:
                flash("A product with that name already exists.", "danger")
            else:
                refresh_products()
                flash("Product updated successfully.", "success")
                return redirect(url_for("admin_products"))
    return render_template(
        "admin/product_form.html",
        product=product,
        categories=CATEGORIES,
        page_title="Edit product",
    )


@app.route("/admin/products/<int:product_id>/delete", methods=["POST"])
@admin_required
def admin_product_delete(product_id):
    if not valid_csrf_token():
        flash("Your form expired. Please try again.", "danger")
        return redirect(url_for("admin_products"))
    database = get_db()
    cursor = database.execute("DELETE FROM products WHERE id = ?", (product_id,))
    database.commit()
    if cursor.rowcount:
        refresh_products()
        flash("Product deleted. Existing order details are preserved.", "success")
    else:
        flash("That product no longer exists.", "warning")
    return redirect(url_for("admin_products"))


@app.route("/admin/orders")
@admin_required
def admin_orders():
    orders = get_db().execute(
        """
        SELECT orders.id, orders.grand_total, orders.status, orders.created_at,
               users.name AS customer_name
        FROM orders
        LEFT JOIN users ON users.id = orders.user_id
        ORDER BY orders.id DESC
        """
    ).fetchall()
    return render_template(
        "admin/orders.html", orders=orders, statuses=ADMIN_ORDER_STATUSES
    )


@app.route("/admin/orders/<int:order_id>")
@admin_required
def admin_order_detail(order_id):
    database = get_db()
    order = database.execute(
        """
        SELECT orders.*, users.name AS customer_name, users.email AS customer_email
        FROM orders
        LEFT JOIN users ON users.id = orders.user_id
        WHERE orders.id = ?
        """,
        (order_id,),
    ).fetchone()
    if order is None:
        return "Order not found", 404
    items = database.execute(
        """
        SELECT product_name, unit_price, quantity, line_total
        FROM order_items
        WHERE order_id = ?
        ORDER BY id
        """,
        (order_id,),
    ).fetchall()
    return render_template(
        "admin/order_detail.html",
        order=order,
        items=items,
        statuses=ADMIN_ORDER_STATUSES,
    )


@app.route("/admin/orders/<int:order_id>/status", methods=["POST"])
@admin_required
def admin_order_status_update(order_id):
    if not valid_csrf_token():
        flash("Your form expired. Please try again.", "danger")
        return redirect(url_for("admin_order_detail", order_id=order_id))
    status = request.form.get("status", "")
    if status not in ADMIN_ORDER_STATUSES:
        flash("Choose a valid order status.", "danger")
    else:
        cursor = get_db().execute(
            "UPDATE orders SET status = ? WHERE id = ?", (status, order_id)
        )
        get_db().commit()
        if cursor.rowcount:
            flash("Order status updated.", "success")
        else:
            flash("That order could not be found.", "warning")
    return redirect(url_for("admin_order_detail", order_id=order_id))


@app.route("/admin/users")
@admin_required
def admin_users():
    users = get_db().execute(
        """
        SELECT users.id, users.name, users.email, COUNT(orders.id) AS order_count
        FROM users
        LEFT JOIN orders ON orders.user_id = users.id
        GROUP BY users.id
        ORDER BY users.id DESC
        """
    ).fetchall()
    return render_template("admin/users.html", users=users)


@app.route("/admin/users/<int:user_id>")
@admin_required
def admin_user_detail(user_id):
    user = get_db().execute(
        """
        SELECT users.id, users.name, users.email, COUNT(orders.id) AS order_count
        FROM users
        LEFT JOIN orders ON orders.user_id = users.id
        WHERE users.id = ?
        GROUP BY users.id
        """,
        (user_id,),
    ).fetchone()
    if user is None:
        return "User not found", 404
    return render_template("admin/user_detail.html", user=user)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if not valid_csrf_token():
            flash("Your form expired. Please try again.", "danger")
            return redirect(url_for("register"))

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not name or len(name) > 100:
            flash("Please enter your name (up to 100 characters).", "danger")
        elif len(email) > 254 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("Please enter a valid email address.", "danger")
        elif len(password) < 8 or len(password) > 128:
            flash("Your password must be between 8 and 128 characters.", "danger")
        elif password != confirm_password:
            flash("The passwords do not match. Please try again.", "danger")
        else:
            database = get_db()
            existing_user = database.execute(
                "SELECT id FROM users WHERE email = ?", (email,)
            ).fetchone()

            if existing_user:
                flash("An account with that email already exists. Please log in.", "warning")
            else:
                password_hash = generate_password_hash(password)
                try:
                    database.execute(
                        "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
                        (name, email, password_hash),
                    )
                    database.commit()
                except sqlite3.IntegrityError:
                    # The unique constraint also handles two registrations arriving together.
                    flash("An account with that email already exists. Please log in.", "warning")
                else:
                    flash("Your account is ready. Please log in.", "success")
                    return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if not valid_csrf_token():
            flash("Your form expired. Please try again.", "danger")
            return redirect(url_for("login"))

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT id, name, email, password_hash FROM users WHERE email = ?",
            (email,),
        ).fetchone()

        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Email or password is incorrect. Please try again.", "danger")
        else:
            # Move the visitor cart into SQLite, while avoiding a duplicate copy
            # when the same user is restoring the cart saved at logout.
            logged_in_user_id = session.get("user_id")
            cart_items = get_cart()
            cart_owner_id = session.get("_cart_owner_id")
            same_user_snapshot = (
                cart_owner_id == user["id"]
                or logged_in_user_id == user["id"]
            )
            switching_accounts = (
                logged_in_user_id is not None and logged_in_user_id != user["id"]
            )
            session.clear()
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            if same_user_snapshot:
                save_cart(cart_items)
            elif cart_items and not switching_accounts:
                move_guest_cart_to_user(user["id"], cart_items)
            flash(f"Welcome back, {user['name']}!", "success")
            next_page = request.args.get("next", "")
            if is_safe_redirect_target(next_page):
                return redirect(next_page)
            return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    if not valid_csrf_token():
        flash("Your form expired. Please try again.", "danger")
        return redirect(url_for("home"))
    cart_items = get_cart()
    user_id = session.get("user_id")
    session.clear()
    if cart_items:
        session["cart"] = cart_items
    if user_id is not None:
        session["_cart_owner_id"] = user_id
    flash("You have been logged out.", "success")
    return redirect(url_for("home"))


@app.route("/account")
@login_required
def dashboard():
    user = get_db().execute(
        "SELECT id, name, email FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    if user is None:
        session.clear()
        flash("Please log in to view your account.", "info")
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=user)


# Start the local development server with: python app.py
if __name__ == "__main__":
    app.run(debug=os.environ.get("SHOP_EASY_DEBUG") == "1")