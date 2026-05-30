from flask import Flask, render_template, request, redirect, url_for, session
import json, os, bcrypt, pyotp

app = Flask(__name__)
app.secret_key = "cle_secrete_2fa_fsbm"

DB_FILE = "users.json"

# ── Helpers ──────────────────────────────────────────────
def load_users():
    if not os.path.exists(DB_FILE):
        return {}
    try:
        with open(DB_FILE, "r") as f:
            content = f.read().strip()
            if not content:
                return {}
            return json.loads(content)
    except json.JSONDecodeError:
        return {}
def save_user(username, email, hashed_pwd, secret):
    users = load_users()
    users[username] = {
        "email": email,
        "password": hashed_pwd,
        "secret": secret
    }
    with open(DB_FILE, "w") as f:
        json.dump(users, f, indent=4)

# ── Routes ────────────────────────────────────────────────

@app.route("/")
def home():
    return redirect(url_for("login"))

# ── Inscription ───────────────────────────────────────────
@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form["username"].strip()
        email    = request.form["email"].strip()
        password = request.form["password"]
        users    = load_users()

        if username in users:
            error = "Nom d'utilisateur déjà utilisé."
        else:
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12)).decode()
            secret = pyotp.random_base32()
            save_user(username, email, hashed, secret)
            return redirect(url_for("login"))

    return render_template("register.html", error=error)

# ── Connexion Phase 1 : mot de passe ─────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        users    = load_users()

        if username not in users:
            error = "Utilisateur introuvable."
        elif not bcrypt.checkpw(password.encode(), users[username]["password"].encode()):
            error = "Mot de passe incorrect."
        else:
            # Phase 1 OK → générer OTP et passer à phase 2
            secret  = users[username]["secret"]
            otp     = pyotp.TOTP(secret).now()
            session["pending_user"] = username
            session["otp_code"]     = otp
            print(f"\n[EMAIL SIMULÉ] Code OTP pour {username} : {otp}\n")
            return redirect(url_for("verify_otp"))

    return render_template("login.html", error=error)

# ── Connexion Phase 2 : vérification OTP ─────────────────
@app.route("/verify", methods=["GET", "POST"])
def verify_otp():
    if "pending_user" not in session:
        return redirect(url_for("login"))

    error = None
    if request.method == "POST":
        token    = request.form["otp"].strip()
        username = session["pending_user"]
        users    = load_users()
        secret   = users[username]["secret"]

        if pyotp.TOTP(secret).verify(token, valid_window=1):
            session.pop("pending_user", None)
            session.pop("otp_code", None)
            session["user"] = username
            return redirect(url_for("dashboard"))
        else:
            error = "Code OTP invalide ou expiré."

    otp_code = session.get("otp_code", "------")
    return render_template("verify_otp.html", error=error, otp_code=otp_code)

# ── Dashboard ─────────────────────────────────────────────
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session["user"])

# ── Déconnexion ───────────────────────────────────────────
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ── Lancement ─────────────────────────────────────────────
if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)