# -----------------------------------------------------------------------------
# YourMarkNet - Marketplace for Sellers, Buyers & Investors
# Copyright (c) 2025 Priyanka
# Licensed for educational and personal use only.
# Commercial use requires prior written permission.
# -----------------------------------------------------------------------------

import os, sqlite3, secrets
from urllib.parse import quote_plus
from functools import wraps
from flask import Flask, g, render_template, request, redirect, url_for, flash, session, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "Yourmark.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
ALLOWED_EXT = {"png", "jpg", "jpeg", "gif"}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024
app.secret_key = secrets.token_hex(16)


# ---------------- DB helpers ----------------
def get_db():
    if "_db" not in g:
        g._db = sqlite3.connect(DB_PATH)
        g._db.row_factory = sqlite3.Row
    return g._db

@app.teardown_appcontext
def close_db(_=None):
    db = g.pop("_db", None)
    if db:
        db.close()

def init_db():
    db = get_db()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT CHECK(role IN ('seller','buyer','investor')) NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      seller_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      description TEXT,
      price REAL NOT NULL,
      image_filename TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(seller_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      seller_id INTEGER NOT NULL,
      buyer_id INTEGER,
      product_id INTEGER NOT NULL,
      type TEXT NOT NULL,            -- 'buy' or 'interview_request'
      message TEXT,
      is_read INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(seller_id) REFERENCES users(id),
      FOREIGN KEY(buyer_id) REFERENCES users(id),
      FOREIGN KEY(product_id) REFERENCES products(id)
    );

    CREATE TABLE IF NOT EXISTS comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      product_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      comment TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(product_id) REFERENCES products(id),
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
                     
    CREATE TABLE IF NOT EXISTS need (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        investor_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        requirements TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (investor_id) REFERENCES users (id)
    );

    CREATE TABLE IF NOT EXISTS pitches (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        requirement_id INTEGER NOT NULL,
        seller_id INTEGER NOT NULL,
        pitch TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (requirement_id) REFERENCES need (id),
        FOREIGN KEY (seller_id) REFERENCES users (id)
    );
    """)
    
# --------------- utilities ------------------
def allowed_file(fname):
    return "." in fname and fname.rsplit(".", 1)[1].lower() in ALLOWED_EXT

def login_required(role=None):
    def deco(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))
            if role and session.get("role") != role:
                flash("Unauthorized for that page.", "danger")
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)
        return wrapper
    return deco

# --------------- routes ---------------------
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("home.html")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        role = request.form.get("role","buyer")
        if not username or not password or role not in ("seller","buyer","investor"):
            flash("Fill all fields correctly.", "danger")
            return render_template("reg.html")
        db = get_db()
        try:
            db.execute("INSERT INTO users (username,password,role) VALUES (?,?,?)",
                       (username, generate_password_hash(password), role))
            db.commit()
            flash("Registered. Please login.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already taken.", "danger")
    return render_template("reg.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        user = get_db().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user and check_password_hash(user["password"], password):
            session.update({"user_id": user["id"], "username": user["username"], "role": user["role"]})
            flash("Login successful.", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid credentials.", "danger")
    return render_template("log.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required()
def dashboard():
    r = session.get("role")
    return redirect(url_for(f"{r}_dashboard"))

# -------- seller --------
@app.route("/seller", methods=["GET","POST"])
@login_required(role="seller")
def seller_dashboard():
    db = get_db()
    sid = session["user_id"]

    if request.method == "POST" and "name" in request.form:
        name = request.form.get("name","").strip()
        description = request.form.get("description","").strip()
        price = request.form.get("price","0").strip()
        file = request.files.get("image")
        if not name or not price:
            flash("Name and price are required.", "danger")
            return redirect(url_for("seller_dashboard"))

        filename = None
        if file and allowed_file(file.filename):
            filename = f"{secrets.token_hex(6)}_{secure_filename(file.filename)}"
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        db.execute("INSERT INTO products (seller_id,name,description,price,image_filename) VALUES (?,?,?,?,?)",
                   (sid, name, description, float(price), filename))
        db.commit()
        flash("Product uploaded.", "success")
        return redirect(url_for("seller_dashboard"))
    
    # Handle pitch submission
    if request.method == "POST":
        requirement_id = request.form.get("requirement_id")
        pitch= request.form.get("pitch","").strip()
        if requirement_id and pitch:
            db.execute("INSERT INTO pitches (requirement_id, seller_id, pitch, created_at) VALUES (?,?,?, CURRENT_TIMESTAMP)",
                       (requirement_id, sid, pitch))
            db.commit()
            flash("Pitch sent to investor.", "success")
            return redirect(url_for("seller_dashboard"))

    products = db.execute("SELECT * FROM products WHERE seller_id=? ORDER BY created_at DESC", (sid,)).fetchall()
    notes = db.execute("""
        SELECT n.*, u.username AS buyer_name, p.name AS product_name
        FROM notifications n
        LEFT JOIN users u ON u.id = n.buyer_id
        LEFT JOIN products p ON p.id = n.product_id
        WHERE n.seller_id=?
        ORDER BY n.created_at DESC
    """, (sid,)).fetchall()

    requirements = db.execute("""
        SELECT r.*, u.username AS investor_name
        FROM need r JOIN users u ON u.id=r.investor_id
        ORDER BY r.created_at DESC
    """).fetchall()

    return render_template("seller.html", products=products, notifications=notes, requirements=requirements)



@app.route("/seller/product/delete/<int:pid>", methods=["POST"])
@login_required(role="seller")
def delete_product(pid):
    db = get_db()
    sid = session["user_id"]
    p = db.execute("SELECT * FROM products WHERE id=? AND seller_id=?", (pid, sid)).fetchone()
    if not p:
        flash("Product not found or not yours.", "danger")
        return redirect(url_for("seller_dashboard"))
    if p["image_filename"]:
        try: os.remove(os.path.join(app.config["UPLOAD_FOLDER"], p["image_filename"]))
        except OSError: pass
    db.execute("DELETE FROM products WHERE id=?", (pid,))
    db.execute("DELETE FROM notifications WHERE product_id=?", (pid,))
    db.execute("DELETE FROM comments WHERE product_id=?", (pid,))
    db.commit()
    flash("Product deleted.", "info")
    return redirect(url_for("seller_dashboard"))

@app.route("/seller/notifications/mark_read/<int:nid>", methods=["POST"])
@login_required(role="seller")
def mark_notification_read(nid):
    db = get_db()
    sid = session["user_id"]
    db.execute("UPDATE notifications SET is_read=1 WHERE id=? AND seller_id=?", (nid, sid))
    db.commit()
    return redirect(url_for("seller_dashboard"))

# -------- buyer --------
@app.route("/buyer")
@login_required(role="buyer")
def buyer_dashboard():
    db = get_db()
    q = request.args.get("q","").strip()
    if q:
        like = f"%{q}%"
        products = db.execute("""
            SELECT p.*, u.username AS seller_name
            FROM products p JOIN users u ON u.id=p.seller_id
            WHERE p.name LIKE ? OR p.description LIKE ?
            ORDER BY p.created_at DESC
        """, (like, like)).fetchall()
    else:
        products = db.execute("""
            SELECT p.*, u.username AS seller_name
            FROM products p JOIN users u ON u.id=p.seller_id
            ORDER BY p.created_at DESC
        """).fetchall()
    return render_template("buyer.html", products=products, query=q)

@app.route("/product/<int:pid>", methods=["GET","POST"])
@login_required()
def view_product(pid):
    db = get_db()
    product = db.execute("""
        SELECT p.*, u.username AS seller_name, u.id AS seller_id
        FROM products p JOIN users u ON u.id=p.seller_id
        WHERE p.id=?
    """, (pid,)).fetchone()
    if not product:
        flash("Product not found.", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        text = request.form.get("comment","").strip()
        if text:
            db.execute("INSERT INTO comments (product_id,user_id,comment) VALUES (?,?,?)",
                       (pid, session["user_id"], text))
            db.commit()
            flash("Comment added.", "success")
            return redirect(url_for("product_view", pid=pid))

    comments = db.execute("""
        SELECT c.*, u.username FROM comments c
        JOIN users u ON u.id=c.user_id
        WHERE c.product_id=?
        ORDER BY c.created_at DESC
    """, (pid,)).fetchall()
    return render_template("product_view.html", product=product, comments=comments)

@app.route("/buy/<int:pid>", methods=["POST"])
@login_required(role="buyer")
def buy_product(pid):
    db = get_db()
    buyer_id = session["user_id"]
    prod = db.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    if not prod:
        flash("Product not found.", "danger")
        return redirect(url_for("buyer_dashboard"))
    db.execute("""
        INSERT INTO notifications (seller_id,buyer_id,product_id,type,message)
        VALUES (?,?,?,?,?)
    """, (prod["seller_id"], buyer_id, pid, "buy",
          f"Buyer {session['username']} is interested in '{prod['name']}'."))
    db.commit()
    flash("Seller notified of your interest.", "success")
    return redirect(url_for("buyer_dashboard"))

# -------- investor --------
@app.route("/investor", methods=["GET","POST"])
@login_required(role="investor")

 
def investor_dashboard():
    db = get_db()
    inv_id = session["user_id"]

        
    if request.method == "POST":
        requirements = request.form.get("requirements","").strip()
        title=request.form.get("title","").strip()
        if requirements and title:
            db.execute("INSERT INTO need (investor_id, requirements, title) VALUES (?,?,?)",
                       (inv_id, requirements,title))
            db.commit()
            flash("Requirements posted. Sellers can now pitch!", "success")
            return redirect(url_for("investor_dashboard"))
    products = get_db().execute("""
        SELECT p.*, u.username AS seller_name
        FROM products p JOIN users u ON u.id=p.seller_id
        ORDER BY p.created_at DESC
    """).fetchall()

    my_reqs=db.execute("SELECT * FROM need WHERE investor_id=? ORDER BY created_at DESC",(inv_id,)).fetchall()

    req_ids = [r["id"] for r in my_reqs]
    if req_ids:
        q_marks = ",".join("?" for _ in req_ids)
        all_pitches = db.execute(f"""
            SELECT pi.*, u.username AS seller_name
            FROM pitches pi
            JOIN users u ON u.id=pi.seller_id
            WHERE pi.requirement_id IN ({q_marks})
            ORDER BY pi.created_at DESC
        """, req_ids).fetchall()
    else:
        all_pitches = []

    # Group pitches by requirement_id
    pitches_by_req = {}
    for p in all_pitches:
        pitches_by_req.setdefault(p["requirement_id"], []).append(p)

    return render_template(
        "investor.html",
        products=products,
        requirements=my_reqs,
        pitches_by_req=pitches_by_req
    )

   
@app.route("/investor/requirement/delete/<int:req_id>", methods=["POST"])
@login_required(role="investor")
def delete_requirement(req_id):
    db = get_db()
    inv_id = session["user_id"]

    # Check that requirement belongs to this investor
    req = db.execute("SELECT * FROM need WHERE id=? AND investor_id=?", (req_id, inv_id)).fetchone()
    if not req:
        flash("Requirement not found or not yours.", "danger")
        return redirect(url_for("investor_dashboard"))

    # Delete pitches linked to this requirement first (to maintain integrity)
    db.execute("DELETE FROM pitches WHERE requirement_id=?", (req_id,))
    # Delete the requirement itself
    db.execute("DELETE FROM need WHERE id=?", (req_id,))
    db.commit()

    flash("Requirement deleted.", "info")
    return redirect(url_for("investor_dashboard"))

    

@app.route("/request_interview/<int:pid>", methods=["POST"])
@login_required(role="investor")
def request_interview(pid):
    db = get_db()
    inv_id = session["user_id"]
    prod = db.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    if not prod:
        flash("Product not found.", "danger")
        return redirect(url_for("investor_dashboard"))
    room = f"Yourmark-{pid}-{secrets.token_hex(4)}"
    jitsi = f"https://meet.jit.si/{quote_plus(room)}"
    msg = f"Investor {session['username']} requested an interview for '{prod['name']}'. Meet link: {jitsi}"
    db.execute("""
        INSERT INTO notifications (seller_id,buyer_id,product_id,type,message)
        VALUES (?,?,?,?,?)
    """, (prod["seller_id"], inv_id, pid, "interview_request", msg))
    db.commit()
    flash("Interview request sent (Jitsi link added for the seller).", "success")
    return redirect(url_for("investor_dashboard"))

# ---- serve uploaded images (optional pretty URL) ----
@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

# --------------- main -----------------------
if __name__ == "__main__":
    with app.app_context():
        init_db()           # <-- creates DB/tables safely inside app context
    app.run(debug=True)