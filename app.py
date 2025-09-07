import os
import sqlite3
import uuid
from datetime import datetime
from flask import Flask, request, render_template, redirect, url_for, session, send_from_directory, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "app.db")
UPLOAD_ROOT = os.path.join(BASE_DIR, "uploads")

ALLOWED_EXTENSIONS = set(["txt","pdf","png","jpg","jpeg","gif","zip","csv","xlsx","docx","pptx","mp3","mp4","avi","mkv","json"])

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        orig_name TEXT NOT NULL,
        stored_name TEXT NOT NULL,
        size_bytes INTEGER NOT NULL,
        mime TEXT,
        uploaded_at TEXT NOT NULL,
        share_token TEXT UNIQUE,
        downloads INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )""")
    conn.commit()
    conn.close()

def ensure_user_folder(user_id):
    path = os.path.join(UPLOAD_ROOT, str(user_id))
    os.makedirs(path, exist_ok=True)
    return path

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_CONTENT_LENGTH_MB", "20")) * 1024 * 1024
    init_db()

    @app.context_processor
    def inject_now():
        return {"now": datetime.utcnow()}

    @app.route("/")
    def index():
        if "user_id" in session:
            return redirect(url_for("files"))
        return render_template("index.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username","").strip().lower()
            password = request.form.get("password","")
            if not username or not password:
                flash("Username and password are required.", "error")
                return render_template("register.html")
            conn = get_db()
            try:
                conn.execute("INSERT INTO users (username, password_hash, created_at) VALUES (?,?,?)",
                             (username, generate_password_hash(password), datetime.utcnow().isoformat()))
                conn.commit()
                flash("Account created. Please log in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("Username already exists.", "error")
            finally:
                conn.close()
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username","").strip().lower()
            password = request.form.get("password","")
            conn = get_db()
            user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            conn.close()
            if user and check_password_hash(user["password_hash"], password):
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                flash("Welcome back!", "success")
                return redirect(url_for("files"))
            flash("Invalid credentials.", "error")
        return render_template("login.html")

    @app.route("/logout")
    def logout():
        session.clear()
        flash("You have been logged out.", "info")
        return redirect(url_for("index"))

    @app.route("/upload", methods=["GET", "POST"])
    def upload():
        if "user_id" not in session:
            return redirect(url_for("login"))
        if request.method == "POST":
            if "file" not in request.files:
                flash("No file part.", "error")
                return redirect(request.url)
            file = request.files["file"]
            if file.filename == "":
                flash("No selected file.", "error")
                return redirect(request.url)
            if file and allowed_file(file.filename):
                user_id = session["user_id"]
                folder = ensure_user_folder(user_id)
                orig_name = secure_filename(file.filename)
                ext = orig_name.rsplit(".",1)[1].lower() if "." in orig_name else ""
                stored_name = f"{uuid.uuid4().hex}.{ext}" if ext else uuid.uuid4().hex
                save_path = os.path.join(folder, stored_name)
                file.save(save_path)
                size_bytes = os.path.getsize(save_path)
                mime = file.mimetype
                conn = get_db()
                conn.execute("""INSERT INTO files (user_id, orig_name, stored_name, size_bytes, mime, uploaded_at)
                                VALUES (?,?,?,?,?,?)""",
                             (user_id, orig_name, stored_name, size_bytes, mime, datetime.utcnow().isoformat()))
                conn.commit()
                conn.close()
                flash("Upload successful.", "success")
                return redirect(url_for("files"))
            else:
                flash("File type not allowed.", "error")
        return render_template("upload.html")

    @app.route("/files")
    def files():
        if "user_id" not in session:
            return redirect(url_for("login"))
        conn = get_db()
        rows = conn.execute("""SELECT id, orig_name, size_bytes, uploaded_at, share_token, downloads
                               FROM files WHERE user_id = ? ORDER BY uploaded_at DESC""", (session["user_id"],)).fetchall()
        conn.close()
        return render_template("files.html", files=rows)

    @app.route("/download/<int:file_id>")
    def download(file_id):
        if "user_id" not in session:
            return redirect(url_for("login"))
        conn = get_db()
        row = conn.execute("SELECT * FROM files WHERE id = ? AND user_id = ?", (file_id, session["user_id"])).fetchone()
        conn.close()
        if not row:
            abort(404)
        path = os.path.join(UPLOAD_ROOT, str(row["user_id"]))
        return send_from_directory(path, row["stored_name"], as_attachment=True, download_name=row["orig_name"])

    @app.route("/share/<int:file_id>", methods=["POST"])
    def share(file_id):
        if "user_id" not in session:
            return redirect(url_for("login"))
        token = uuid.uuid4().hex
        conn = get_db()
        cur = conn.execute("UPDATE files SET share_token = ? WHERE id = ? AND user_id = ?", (token, file_id, session["user_id"]))
        conn.commit()
        conn.close()
        if cur.rowcount == 0:
            abort(404)
        flash("Share link created.", "success")
        return redirect(url_for("files"))

    @app.route("/unshare/<int:file_id>", methods=["POST"])
    def unshare(file_id):
        if "user_id" not in session:
            return redirect(url_for("login"))
        conn = get_db()
        cur = conn.execute("UPDATE files SET share_token = NULL WHERE id = ? AND user_id = ?", (file_id, session["user_id"]))
        conn.commit()
        conn.close()
        if cur.rowcount == 0:
            abort(404)
        flash("Share link removed.", "info")
        return redirect(url_for("files"))

    @app.route("/s/<token>")
    def public_download(token):
        conn = get_db()
        row = conn.execute("SELECT * FROM files WHERE share_token = ?", (token,)).fetchone()
        if not row:
            conn.close()
            abort(404)
        conn.execute("UPDATE files SET downloads = downloads + 1 WHERE id = ?", (row["id"],))
        conn.commit()
        conn.close()
        path = os.path.join(UPLOAD_ROOT, str(row["user_id"]))
        return send_from_directory(path, row["stored_name"], as_attachment=True, download_name=row["orig_name"])

    @app.errorhandler(413)
    def too_large(e):
        return render_template("error.html", message="File too large."), 413

    return app

if __name__ == "__main__":
    app = create_app()
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    app.run(host=host, port=port, debug=True)
