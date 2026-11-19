# ShopEasy

ShopEasy is a beginner-friendly e-commerce demo built with Python, Flask, SQLite, Jinja templates, HTML, CSS, JavaScript, and Bootstrap 5.

The project is intended for local development and learning. It is not deployed, and checkout does not process payments.

## Features

- Responsive homepage with ShopEasy branding, categories, and featured products
- Product listing with name search and category filters
- Customer registration with duplicate-email validation and Werkzeug password hashing
- Customer login, protected account page, and logout
- Guest shopping cart and persistent SQLite carts for signed-in customers
- Demo checkout that records orders and order items in SQLite without payment processing
- Separate administrator login and dashboard
- Admin product create, edit, and delete operations
- Admin order details and status management
- Admin customer list and detail pages with password data kept private

## Technologies

- Python 3.10 or later
- Flask 3.1
- SQLite (included with Python)
- Jinja templates, HTML, CSS, JavaScript
- Bootstrap 5 and Bootstrap Icons (loaded from a CDN in the page templates)

## Local setup (Windows / VS Code)

Open PowerShell in the project directory:

```powershell
cd "C:\path\to\ShopEasy"
py -3 -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell blocks activation, allow scripts for the current terminal session or run the commands using `.\venv\Scripts\python.exe` instead.

Start the local development server:

```powershell
python app.py
```

Open <http://127.0.0.1:5000>. Debug mode is off by default. To explicitly enable the Flask debugger during local development only:

```powershell
$env:SHOP_EASY_DEBUG = "1"
python app.py
```

Do not enable the debugger on an internet-accessible server.

## Database

The app automatically creates and updates its SQLite database at `instance\shopeasy.sqlite3` when it starts. The database and generated local secret key are ignored by Git because they may contain personal data or private session-signing material.

The database contains:

- `users`: customer accounts and password hashes
- `admin_users`: admin accounts and password hashes
- `products`: product catalogue
- `cart_items`: signed-in customer carts
- `orders`: demo order totals, status, and timestamp
- `order_items`: product name/price snapshots for each order
- `app_metadata`: internal one-time sample-product seed marker

SQLite can be inspected with DB Browser for SQLite or the Python `sqlite3` module. Do not share or commit a database containing real customer data.

## Create the initial admin account

There are no default admin credentials. Create the first admin interactively from the project directory:

```powershell
.\venv\Scripts\Activate.ps1
python -m flask --app app create-admin
```

Enter an admin name, username, and a unique password of at least 12 characters when prompted. The password prompt does not display the password; the application stores only its Werkzeug hash. Keep the password in a password manager. The command is a one-time bootstrap and refuses to create another admin once an admin account exists.

Sign in at <http://127.0.0.1:5000/admin/login>. Normal customer accounts do not have administrator access.

## Useful local checks

```powershell
python -m py_compile app.py
python -m flask --app app routes
python -m flask --app app --help
```

There is not currently a committed automated test suite. The application has been exercised with isolated Flask/SQLite integration checks during development.

## Before deployment

This project has not been deployed. Before exposing it publicly:

1. Use a strong random `SHOP_EASY_SECRET_KEY` supplied through the hosting environment; never commit it. The generated `instance\.secret_key` is for local development only.
2. Run behind a production WSGI server and HTTPS; set `SHOP_EASY_HTTPS_ONLY=1` to enable secure session cookies. Do not use Flask's development server or enable `SHOP_EASY_DEBUG`.
3. Review CSRF, session, logging, backups, and database access policies.
4. Decide how to migrate and protect SQLite data, especially for concurrent or multi-instance workloads.
5. Add automated tests and review error handling, privacy, accessibility, and operational monitoring.
6. Confirm product images/CDN assets are acceptable for your deployment environment.

No AWS deployment or real payment processing is configured.
