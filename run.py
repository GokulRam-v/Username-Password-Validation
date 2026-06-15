# -*- coding: utf-8 -*-
"""
Run this one file to start the entire app:

    python run.py

Browser opens automatically at http://localhost:3000
"""

import re
import json
import time
import secrets
import threading
import webbrowser
from pathlib import Path
from collections import defaultdict

import bcrypt
from flask import Flask, request, jsonify, make_response

# ── App setup ──────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# ── JSON file path (sits next to run.py) ──────────────────────────────────
DB_FILE = Path(__file__).parent / "users.json"

# ── Persist helpers ────────────────────────────────────────────────────────

def load_users():
    """Load users from users.json. Returns dict keyed by username_lower."""
    if not DB_FILE.exists():
        return {}
    try:
        raw = json.loads(DB_FILE.read_text(encoding="utf-8"))
        # password_hash is stored as a string; convert back to bytes for bcrypt
        return {
            k: {**v, "password_hash": v["password_hash"].encode()}
            for k, v in raw.items()
        }
    except Exception:
        return {}


def save_users():
    """Write the current users dict to users.json (hashes stored as strings)."""
    serialisable = {
        k: {**v, "password_hash": v["password_hash"].decode()}
        for k, v in users.items()
    }
    DB_FILE.write_text(
        json.dumps(serialisable, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )


# ── In-memory stores ───────────────────────────────────────────────────────
users    = load_users()            # pre-loaded from JSON on startup
sessions = {}                      # token -> { username, last_active }
failures = defaultdict(list)       # username_lower -> [timestamps]

# ── Rules ──────────────────────────────────────────────────────────────────
USERNAME_RE   = re.compile(r'^[a-zA-Z][a-zA-Z0-9_-]{2,19}$')
RESERVED      = {"admin","root","support","system","superuser",
                 "administrator","moderator","staff"}
COMMON_PW     = {"password123","qwerty123456","123456789012",
                 "letmein123456","welcome12345","monkey123456"}
MAX_ATTEMPTS  = 5
LOCKOUT_SEC   = 15 * 60   # 15 min
SESSION_SEC   = 30 * 60   # 30 min idle

# timing-safe dummy hash used when username not found
_DUMMY = bcrypt.hashpw(b"dummy-timing", bcrypt.gensalt())

# ── Helpers ────────────────────────────────────────────────────────────────

def validate_username(u):
    u = (u or "").strip()
    if not u:
        return "Username is required."
    if not USERNAME_RE.match(u):
        return "3–20 chars, start with a letter, only letters/digits/_ or -."
    if u.lower() in RESERVED:
        return "That username is unavailable. Try another."
    return None


def validate_password(p, username=""):
    p = (p or "").strip()
    if not p:                          return "Password is required."
    if len(p) < 8:                     return "Password must be at least 8 characters."
    if len(p) > 128:                   return "Password must be at most 128 characters."
    if not re.search(r'[A-Z]', p):    return "Must include an uppercase letter."
    if not re.search(r'[a-z]', p):    return "Must include a lowercase letter."
    if not re.search(r'\d', p):       return "Must include a digit."
    if not re.search(r'[^A-Za-z0-9]', p): return "Must include a special character (!@#$ etc.)."
    if p.lower() in COMMON_PW:        return "Password is too common. Choose a different one."
    if username and username.lower() in p.lower():
        return "Password must not contain your username."
    return None


def strength(p):
    p = (p or "").strip()
    s = 0
    if len(p) >= 16: s += 2
    elif len(p) >= 12: s += 1
    for pat in (r'[A-Z]', r'[a-z]', r'\d', r'[^A-Za-z0-9]'):
        if re.search(pat, p): s += 1
    if len(set(p)) > 10: s += 1
    return "strong" if s >= 6 else "medium" if s >= 4 else "weak"


def is_locked(key):
    cutoff = time.time() - LOCKOUT_SEC
    failures[key] = [t for t in failures[key] if t > cutoff]
    return len(failures[key]) >= MAX_ATTEMPTS


def get_session(token):
    s = sessions.get(token)
    if not s: return None
    if time.time() - s["last_active"] > SESSION_SEC:
        sessions.pop(token, None); return None
    s["last_active"] = time.time()
    return s["username"]

# ── API ────────────────────────────────────────────────────────────────────

@app.route("/api/check-username", methods=["POST"])
def api_check_username():
    u = (request.get_json(silent=True) or {}).get("username", "").strip()
    err = validate_username(u)
    if err:
        return jsonify(valid=False, error=err)
    if u.lower() in users:
        return jsonify(valid=False, error="That username is unavailable. Try another.")
    return jsonify(valid=True, message="Username is available ✓")


@app.route("/api/check-password", methods=["POST"])
def api_check_password():
    d = request.get_json(silent=True) or {}
    p, u = d.get("password", ""), d.get("username", "")
    err = validate_password(p, u)
    return jsonify(valid=not err, error=err, strength=strength(p))


@app.route("/api/register", methods=["POST"])
def api_register():
    d = request.get_json(silent=True) or {}
    username = (d.get("username") or "").strip()
    password = (d.get("password") or "").strip()

    err = validate_username(username)
    if err: return jsonify(error=err), 400
    if username.lower() in users:
        return jsonify(error="That username is unavailable. Try another."), 400
    err = validate_password(password, username)
    if err: return jsonify(error=err), 400

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
    users[username.lower()] = {"username": username, "password_hash": hashed}
    save_users()   # persist to users.json
    return jsonify(message="Account created! You can now log in."), 201


@app.route("/api/login", methods=["POST"])
def api_login():
    d = request.get_json(silent=True) or {}
    username = (d.get("username") or "").strip()
    password = (d.get("password") or "")
    key = username.lower()

    if is_locked(key):
        return jsonify(error="Too many attempts. Try again in 15 minutes."), 429

    user = users.get(key)
    if user is None:
        bcrypt.checkpw(b"x", _DUMMY)          # timing-safe dummy check
        failures[key].append(time.time())
        return jsonify(error="Invalid username or password."), 401

    if not bcrypt.checkpw(password.encode(), user["password_hash"]):
        failures[key].append(time.time())
        return jsonify(error="Invalid username or password."), 401

    failures[key] = []
    token = secrets.token_urlsafe(48)
    sessions[token] = {"username": user["username"], "last_active": time.time()}

    resp = make_response(jsonify(message="Login successful.", username=user["username"]))
    resp.set_cookie("sid", token, httponly=True, samesite="Strict", max_age=SESSION_SEC)
    return resp


@app.route("/api/logout", methods=["POST"])
def api_logout():
    token = request.cookies.get("sid")
    sessions.pop(token, None)
    resp = make_response(jsonify(message="Logged out."))
    resp.delete_cookie("sid")
    return resp


@app.route("/api/me")
def api_me():
    username = get_session(request.cookies.get("sid"))
    if not username:
        return jsonify(error="Not authenticated."), 401
    return jsonify(username=username)


@app.route("/api/reset-password", methods=["POST"])
def api_reset_password():
    """Change password for the currently logged-in user."""
    username = get_session(request.cookies.get("sid"))
    if not username:
        return jsonify(error="Not authenticated."), 401

    d = request.get_json(silent=True) or {}
    current  = (d.get("current")  or "")
    new_pw   = (d.get("new_pw")   or "").strip()
    confirm  = (d.get("confirm")  or "").strip()

    user = users.get(username.lower())
    if not user:
        return jsonify(error="User not found."), 404

    # Verify current password
    if not bcrypt.checkpw(current.encode(), user["password_hash"]):
        return jsonify(error="Current password is incorrect."), 400

    # New and confirm must match
    if new_pw != confirm:
        return jsonify(error="New passwords do not match."), 400

    # Validate new password
    err = validate_password(new_pw, username)
    if err:
        return jsonify(error=err), 400

    # Must differ from current password
    if bcrypt.checkpw(new_pw.encode(), user["password_hash"]):
        return jsonify(error="New password must be different from your current password."), 400

    # Hash and save
    user["password_hash"] = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt(rounds=12))
    save_users()

    # Invalidate all sessions so user must log in again
    token = request.cookies.get("sid")
    for t in list(sessions):
        if sessions[t]["username"] == username:
            del sessions[t]

    resp = make_response(jsonify(message="Password reset successfully. Please log in again."))
    resp.delete_cookie("sid")
    return resp, 200

# ── UI (single inline HTML page) ──────────────────────────────────────────

PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>User Authentication</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --brand:#6366f1;--brand-dk:#4338ca;--brand-lt:#e0e7ff;
  --red:#ef4444;--red-bg:#fef2f2;--green:#22c55e;--green-bg:#f0fdf4;
  --amber:#f59e0b;--text:#0f172a;--sub:#64748b;--border:#e2e8f0;
  --bg:#0f172a;--card:rgba(255,255,255,0.05);--r:18px;
  --sh:0 25px 60px rgba(0,0,0,.5);--glow:0 0 40px rgba(99,102,241,.3)
}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
  background:var(--bg);color:#e2e8f0;min-height:100vh;
  display:flex;flex-direction:column;align-items:center;padding:2.5rem 1rem;
  overflow-x:hidden;position:relative}

/* ── animated background ── */
body::before{
  content:'';position:fixed;inset:0;
  background:radial-gradient(ellipse at 20% 50%,rgba(99,102,241,.15) 0%,transparent 60%),
             radial-gradient(ellipse at 80% 20%,rgba(139,92,246,.12) 0%,transparent 50%),
             radial-gradient(ellipse at 60% 80%,rgba(59,130,246,.1) 0%,transparent 50%);
  animation:bgshift 8s ease-in-out infinite alternate;pointer-events:none;z-index:0}
@keyframes bgshift{
  0%{background:radial-gradient(ellipse at 20% 50%,rgba(99,102,241,.18) 0%,transparent 60%),
               radial-gradient(ellipse at 80% 20%,rgba(139,92,246,.14) 0%,transparent 50%),
               radial-gradient(ellipse at 60% 80%,rgba(59,130,246,.1) 0%,transparent 50%)}
  100%{background:radial-gradient(ellipse at 70% 30%,rgba(99,102,241,.18) 0%,transparent 60%),
                radial-gradient(ellipse at 20% 80%,rgba(139,92,246,.14) 0%,transparent 50%),
                radial-gradient(ellipse at 80% 60%,rgba(59,130,246,.12) 0%,transparent 50%)}
}

/* ── floating particles canvas ── */
#particles{position:fixed;inset:0;pointer-events:none;z-index:0}

/* ── grid overlay ── */
body::after{
  content:'';position:fixed;inset:0;
  background-image:linear-gradient(rgba(99,102,241,.04) 1px,transparent 1px),
                   linear-gradient(90deg,rgba(99,102,241,.04) 1px,transparent 1px);
  background-size:60px 60px;pointer-events:none;z-index:0}

header,main,#toast{position:relative;z-index:1}

/* ── header ── */
header{width:100%;max-width:440px;display:flex;justify-content:space-between;
  align-items:center;margin-bottom:2rem;
  animation:slidedown .7s cubic-bezier(.22,1,.36,1)}
@keyframes slidedown{from{opacity:0;transform:translateY(-24px)}to{opacity:1;transform:none}}
.logo{font-size:1.2rem;font-weight:800;
  background:linear-gradient(135deg,#818cf8,#c084fc);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  background-clip:text;letter-spacing:-.5px}
#hdr-right{display:flex;align-items:center;gap:.6rem;font-size:.85rem}
#hdr-name{font-weight:700;color:#c7d2fe}
.btn-sm{background:rgba(99,102,241,.15);border:1px solid rgba(99,102,241,.3);
  color:#a5b4fc;padding:.3rem .75rem;border-radius:6px;
  font-size:.8rem;font-weight:600;cursor:pointer;transition:.2s}
.btn-sm:hover{background:rgba(99,102,241,.3);border-color:#818cf8;color:#fff}

/* ── card ── */
.card{
  background:rgba(15,23,42,.7);
  backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);
  border:1px solid rgba(99,102,241,.2);
  border-radius:var(--r);box-shadow:var(--sh),var(--glow);
  width:100%;max-width:440px;overflow:hidden;position:relative;z-index:1;
  animation:cardin .8s cubic-bezier(.22,1,.36,1)}
@keyframes cardin{
  from{opacity:0;transform:translateY(40px) scale(.97)}
  to{opacity:1;transform:none}}
.card::before{
  content:'';position:absolute;top:0;left:-100%;width:60%;height:2px;
  background:linear-gradient(90deg,transparent,rgba(99,102,241,.8),transparent);
  animation:scanline 4s linear infinite}
@keyframes scanline{to{left:200%}}

/* ── tabs ── */
.tabs{display:flex;border-bottom:1px solid rgba(99,102,241,.15)}
.tab{flex:1;padding:.9rem;background:none;border:none;cursor:pointer;
  font-size:.9rem;font-weight:600;color:var(--sub);
  border-bottom:2px solid transparent;margin-bottom:-1px;
  transition:all .25s;position:relative;overflow:hidden}
.tab::after{content:'';position:absolute;inset:0;
  background:linear-gradient(135deg,rgba(99,102,241,.08),transparent);
  opacity:0;transition:.25s}
.tab:hover{color:#a5b4fc}
.tab:hover::after{opacity:1}
.tab.on{color:#818cf8;border-bottom-color:#6366f1}
.tab.on::after{opacity:1}

/* ── panel ── */
.panel{padding:1.75rem}
.panel.hidden{display:none}
h2{font-size:1.15rem;font-weight:700;margin-bottom:1.5rem;
  background:linear-gradient(135deg,#e2e8f0,#a5b4fc);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}

/* ── field ── */
.field{margin-bottom:1rem;
  animation:fieldin .5s cubic-bezier(.22,1,.36,1) both}
@keyframes fieldin{from{opacity:0;transform:translateX(-12px)}to{opacity:1;transform:none}}
.field:nth-child(1){animation-delay:.05s}
.field:nth-child(2){animation-delay:.1s}
.field:nth-child(3){animation-delay:.15s}
label{display:block;font-size:.8rem;font-weight:600;margin-bottom:.3rem;
  color:#94a3b8;text-transform:uppercase;letter-spacing:.05em}
.row{position:relative;display:flex;align-items:center}
input{width:100%;padding:.7rem 1rem;
  border:1.5px solid rgba(99,102,241,.2);border-radius:9px;
  font-size:.92rem;outline:none;
  background:rgba(15,23,42,.6);color:#e2e8f0;
  transition:all .25s;
  caret-color:#818cf8}
input::placeholder{color:#475569}
input:focus{
  border-color:#6366f1;
  box-shadow:0 0 0 3px rgba(99,102,241,.2),0 0 20px rgba(99,102,241,.1);
  background:rgba(15,23,42,.8)}
input.bad{border-color:#ef4444;box-shadow:0 0 0 3px rgba(239,68,68,.15)}
input.good{border-color:#22c55e;box-shadow:0 0 0 3px rgba(34,197,94,.12)}
.eye{position:absolute;right:.75rem;background:none;border:none;
  cursor:pointer;font-size:.95rem;opacity:.35;padding:0;line-height:1;transition:.2s}
.eye:hover{opacity:.9;transform:scale(1.1)}
.icon{position:absolute;right:.75rem;font-size:.85rem;pointer-events:none}
.hint{font-size:.74rem;color:#475569;margin-top:.25rem}
.ferr{font-size:.75rem;color:#f87171;min-height:.85rem;margin-top:.25rem;
  animation:ferrin .2s ease}
@keyframes ferrin{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:none}}

/* ── strength bar ── */
.sbar{display:flex;align-items:center;gap:.5rem;margin-top:.4rem}
.track{flex:1;height:4px;background:rgba(255,255,255,.08);border-radius:99px;overflow:hidden}
.fill{height:100%;width:0;border-radius:99px;transition:width .4s cubic-bezier(.34,1.56,.64,1),background .3s}
.slbl{font-size:.72rem;font-weight:700;min-width:3rem;transition:color .3s}
.weak   .fill{width:33%;background:linear-gradient(90deg,#ef4444,#f87171)}
.medium .fill{width:66%;background:linear-gradient(90deg,#f59e0b,#fbbf24)}
.strong .fill{width:100%;background:linear-gradient(90deg,#22c55e,#4ade80)}
.weak   .slbl{color:#f87171}
.medium .slbl{color:#fbbf24}
.strong .slbl{color:#4ade80}

/* ── alert boxes ── */
.alert{padding:.65rem .9rem;border-radius:8px;font-size:.82rem;
  display:none;margin-bottom:.9rem;animation:alertin .3s ease}
@keyframes alertin{from{opacity:0;transform:scale(.97)}to{opacity:1;transform:none}}
.alert.on{display:block}
.alert.err{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);color:#fca5a5}
.alert.ok{background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.3);color:#86efac}

/* ── primary button ── */
.btn{width:100%;padding:.75rem;border:none;border-radius:9px;cursor:pointer;
  font-size:.93rem;font-weight:700;color:#fff;
  background:linear-gradient(135deg,#6366f1,#8b5cf6);
  display:flex;align-items:center;justify-content:center;gap:.4rem;
  transition:all .25s;position:relative;overflow:hidden;
  box-shadow:0 4px 20px rgba(99,102,241,.35)}
.btn::before{
  content:'';position:absolute;top:0;left:-100%;width:50%;height:100%;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,.15),transparent);
  transition:left .5s}
.btn:hover:not(:disabled){
  background:linear-gradient(135deg,#4f46e5,#7c3aed);
  box-shadow:0 6px 28px rgba(99,102,241,.5);
  transform:translateY(-1px)}
.btn:hover:not(:disabled)::before{left:150%}
.btn:active:not(:disabled){transform:translateY(0)}
.btn:disabled{opacity:.45;cursor:not-allowed}

/* ── footer link ── */
.ftr{text-align:center;font-size:.8rem;color:#475569;margin-top:1rem}
.lnk{background:none;border:none;color:#818cf8;font-size:inherit;
  font-weight:600;cursor:pointer;text-decoration:underline;
  transition:color .2s}
.lnk:hover{color:#c4b5fd}

/* ── spinner ── */
.spin{width:14px;height:14px;border:2px solid rgba(255,255,255,.3);
  border-top-color:#fff;border-radius:50%;animation:sp .6s linear infinite}
@keyframes sp{to{transform:rotate(360deg)}}

/* ── dashboard ── */
.dash{padding:1.75rem}
.dash-header{display:flex;align-items:center;justify-content:space-between;
  margin-bottom:1.25rem;flex-wrap:wrap;gap:.75rem}
.dash-title{font-size:1.1rem;font-weight:700;
  background:linear-gradient(135deg,#e2e8f0,#a5b4fc);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.dtop{display:flex;align-items:center;gap:1rem;margin-bottom:1.25rem}
.av{width:56px;height:56px;border-radius:50%;flex-shrink:0;
  background:linear-gradient(135deg,#6366f1,#8b5cf6);
  color:#fff;font-size:1.4rem;font-weight:800;
  display:flex;align-items:center;justify-content:center;
  box-shadow:0 0 0 3px rgba(99,102,241,.3),0 0 20px rgba(99,102,241,.4);
  animation:avpop .6s cubic-bezier(.34,1.56,.64,1)}
@keyframes avpop{from{transform:scale(0) rotate(-180deg)}to{transform:scale(1) rotate(0)}}
.dtop h2{font-size:1.1rem;font-weight:700;color:#e2e8f0;margin-bottom:.1rem}
.dtop p{font-size:.8rem;color:#64748b}
.badge{display:inline-flex;align-items:center;gap:.35rem;
  background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.3);color:#4ade80;
  border-radius:99px;padding:.25rem .8rem;font-size:.78rem;font-weight:700;
  margin-bottom:1.25rem;animation:badgein .5s .3s cubic-bezier(.34,1.56,.64,1) both}
@keyframes badgein{from{opacity:0;transform:scale(.7)}to{opacity:1;transform:scale(1)}}
.dactions{display:flex;gap:.6rem;justify-content:flex-end;margin-top:1.25rem}
.btn-out{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);
  color:#fca5a5;padding:.38rem .9rem;border-radius:7px;
  font-size:.82rem;font-weight:700;cursor:pointer;transition:.2s}
.btn-out:hover{background:rgba(239,68,68,.25);border-color:#ef4444;color:#fff}

/* ── reset section ── */
.divider{border:none;border-top:1px solid rgba(99,102,241,.15);margin:1.25rem 0}
.section-title{font-size:.75rem;font-weight:700;color:#475569;
  text-transform:uppercase;letter-spacing:.1em;margin-bottom:1rem}

/* ── toast ── */
#toast{position:fixed;bottom:1.75rem;left:50%;transform:translateX(-50%) translateY(20px);
  padding:.65rem 1.25rem;border-radius:10px;font-size:.85rem;color:#fff;
  background:rgba(15,23,42,.95);
  border:1px solid rgba(99,102,241,.3);
  box-shadow:0 8px 32px rgba(0,0,0,.4),0 0 20px rgba(99,102,241,.2);
  backdrop-filter:blur(12px);
  opacity:0;pointer-events:none;
  transition:opacity .3s,transform .3s cubic-bezier(.34,1.56,.64,1);
  z-index:99;max-width:88vw;text-align:center}
#toast.on{opacity:1;pointer-events:auto;transform:translateX(-50%) translateY(0)}
#toast.s{border-color:rgba(34,197,94,.4);box-shadow:0 8px 32px rgba(0,0,0,.4),0 0 20px rgba(34,197,94,.2)}
#toast.e{border-color:rgba(239,68,68,.4);box-shadow:0 8px 32px rgba(0,0,0,.4),0 0 20px rgba(239,68,68,.2)}

/* ── page transition overlay ── */
#curtain{position:fixed;inset:0;background:#0f172a;
  z-index:200;pointer-events:none;opacity:0;transition:opacity .4s}
#curtain.show{opacity:1;pointer-events:auto}

.hidden{display:none!important}

/* ── pulse ring on avatar ── */
.av-wrap{position:relative;flex-shrink:0}
.av-wrap::after{
  content:'';position:absolute;inset:-6px;border-radius:50%;
  border:2px solid rgba(99,102,241,.4);
  animation:pulse-ring 2s ease-out infinite}
@keyframes pulse-ring{
  0%{transform:scale(1);opacity:.6}
  100%{transform:scale(1.35);opacity:0}}
</style>
</head>
<body>
<canvas id="particles"></canvas>
<div id="curtain"></div>

<header>
  <span class="logo">&#128274; User Authentication</span>
  <div id="hdr-right" class="hidden">
    <span id="hdr-name"></span>
    <button class="btn-sm" id="hdr-logout">Logout</button>
  </div>
</header>

<!-- ── Auth card ── -->
<div class="card" id="auth-card">
  <div class="tabs">
    <button class="tab on" data-tab="login">Login</button>
    <button class="tab"    data-tab="register">Register</button>
  </div>

  <!-- Login panel -->
  <div class="panel" id="p-login">
    <h2>Welcome back</h2>
    <form id="f-login" novalidate>
      <div class="field">
        <label for="l-u">Username</label>
        <div class="row">
          <input id="l-u" type="text" autocomplete="username" placeholder="Enter username" required/>
        </div>
        <div class="ferr" id="l-u-e"></div>
      </div>
      <div class="field">
        <label for="l-p">Password</label>
        <div class="row">
          <input id="l-p" type="password" autocomplete="current-password" placeholder="Enter password" required/>
          <button type="button" class="eye" data-t="l-p">&#128065;</button>
        </div>
        <div class="ferr" id="l-p-e"></div>
      </div>
      <div class="alert err" id="l-box"></div>
      <button type="submit" class="btn" id="btn-login">Login</button>
    </form>
    <div class="ftr">No account? <button class="lnk" data-tab="register">Create one</button></div>
  </div>

  <!-- Register panel -->
  <div class="panel hidden" id="p-register">
    <h2>Create account</h2>
    <form id="f-register" novalidate>
      <div class="field">
        <label for="r-u">Username</label>
        <div class="row">
          <input id="r-u" type="text" autocomplete="username"
                 placeholder="3&#8211;20 chars, letters/digits/_ or -" required/>
          <span class="icon" id="r-u-icon"></span>
        </div>
        <div class="hint">Must start with a letter.</div>
        <div class="ferr" id="r-u-e"></div>
      </div>
      <div class="field">
        <label for="r-p">Password</label>
        <div class="row">
          <input id="r-p" type="password" autocomplete="new-password"
                 placeholder="Min 8 characters" required/>
          <button type="button" class="eye" data-t="r-p">&#128065;</button>
        </div>
        <div class="sbar" id="sbar">
          <div class="track"><div class="fill" id="s-fill"></div></div>
          <span class="slbl" id="s-lbl"></span>
        </div>
        <div class="ferr" id="r-p-e"></div>
      </div>
      <div class="field">
        <label for="r-p2">Confirm Password</label>
        <div class="row">
          <input id="r-p2" type="password" autocomplete="new-password"
                 placeholder="Repeat password" required/>
          <button type="button" class="eye" data-t="r-p2">&#128065;</button>
        </div>
        <div class="ferr" id="r-p2-e"></div>
      </div>
      <div class="alert err" id="r-box"></div>
      <button type="submit" class="btn" id="btn-reg">Create Account</button>
    </form>
    <div class="ftr">Have an account? <button class="lnk" data-tab="login">Log in</button></div>
  </div>
</div>

<!-- ── Dashboard ── -->
<div class="card hidden" id="dash-card">
  <div class="dash">

    <div class="dash-header">
      <h2 class="dash-title">&#128274; User Authentication</h2>
      <span class="badge">&#10003; Logged in</span>
    </div>

    <hr class="divider"/>
    <div class="section-title">Reset Password</div>
    <form id="f-reset" novalidate>
      <div class="field">
        <label for="rp-cur">Current Password</label>
        <div class="row">
          <input id="rp-cur" type="password" autocomplete="current-password"
                 placeholder="Enter current password" required/>
          <button type="button" class="eye" data-t="rp-cur">&#128065;</button>
        </div>
        <div class="ferr" id="rp-cur-e"></div>
      </div>
      <div class="field">
        <label for="rp-new">New Password</label>
        <div class="row">
          <input id="rp-new" type="password" autocomplete="new-password"
                 placeholder="Min 8 characters" required/>
          <button type="button" class="eye" data-t="rp-new">&#128065;</button>
        </div>
        <div class="sbar" id="rp-sbar">
          <div class="track"><div class="fill" id="rp-fill"></div></div>
          <span class="slbl" id="rp-lbl"></span>
        </div>
        <div class="ferr" id="rp-new-e"></div>
      </div>
      <div class="field">
        <label for="rp-con">Confirm New Password</label>
        <div class="row">
          <input id="rp-con" type="password" autocomplete="new-password"
                 placeholder="Repeat new password" required/>
          <button type="button" class="eye" data-t="rp-con">&#128065;</button>
        </div>
        <div class="ferr" id="rp-con-e"></div>
      </div>
      <div class="alert err" id="rp-err"></div>
      <div class="alert ok"  id="rp-ok"></div>
      <button type="submit" class="btn" id="btn-reset">Reset Password</button>
    </form>

    <div class="dactions">
      <button class="btn-out" id="d-logout">Logout</button>
    </div>
  </div>
</div>

<div id="toast"></div>

<script>
"use strict";
const $ = id => document.getElementById(id);

/* ── Particle system ─────────────────────────────────────── */
(function(){
  const cv = $("particles"), cx = cv.getContext("2d");
  let W, H, pts = [];
  function resize(){ W = cv.width = innerWidth; H = cv.height = innerHeight; }
  resize(); addEventListener("resize", resize);
  function rand(a,b){ return a + Math.random()*(b-a); }
  for(let i=0;i<70;i++) pts.push({
    x:rand(0,innerWidth), y:rand(0,innerHeight),
    r:rand(.5,2), vx:rand(-.25,.25), vy:rand(-.4,-.1),
    a:rand(.2,.7), va:rand(-.005,.005)
  });
  function frame(){
    cx.clearRect(0,0,W,H);
    pts.forEach(p=>{
      p.x+=p.vx; p.y+=p.vy; p.a+=p.va;
      if(p.a<.1||p.a>.8) p.va*=-1;
      if(p.y<-5) p.y=H+5;
      if(p.x<-5) p.x=W+5;
      if(p.x>W+5) p.x=-5;
      cx.beginPath();
      cx.arc(p.x,p.y,p.r,0,Math.PI*2);
      cx.fillStyle=`rgba(139,92,246,${p.a})`;
      cx.fill();
    });
    /* draw faint connection lines */
    pts.forEach((a,i)=>pts.slice(i+1).forEach(b=>{
      const dx=a.x-b.x, dy=a.y-b.y, dist=Math.sqrt(dx*dx+dy*dy);
      if(dist<120){
        cx.beginPath(); cx.moveTo(a.x,a.y); cx.lineTo(b.x,b.y);
        cx.strokeStyle=`rgba(99,102,241,${.12*(1-dist/120)})`;
        cx.lineWidth=.6; cx.stroke();
      }
    }));
    requestAnimationFrame(frame);
  }
  frame();
})();

/* ── Page curtain transition ──────────────────────────────── */
function curtainOut(cb){
  const c=$("curtain"); c.classList.add("show");
  setTimeout(()=>{ cb(); c.classList.remove("show"); },400);
}

/* ── Tabs ─────────────────────────────────────────────────── */
function tab(name){
  document.querySelectorAll(".tab").forEach(t=>t.classList.toggle("on",t.dataset.tab===name));
  $("p-login").classList.toggle("hidden",name!=="login");
  $("p-register").classList.toggle("hidden",name!=="register");
  reset();
}
document.querySelectorAll(".tab,.lnk[data-tab]").forEach(el=>
  el.addEventListener("click",()=>tab(el.dataset.tab)));

/* ── Eye toggles ──────────────────────────────────────────── */
document.querySelectorAll(".eye").forEach(b=>
  b.addEventListener("click",()=>{
    const i=$(b.dataset.t);
    i.type=i.type==="text"?"password":"text";
    b.innerHTML=i.type==="text"?"&#128584;":"&#128065;";
  }));

/* ── Toast ────────────────────────────────────────────────── */
let _tt;
function toast(msg,t=""){
  const el=$("toast"); el.textContent=msg; el.className="on "+t;
  clearTimeout(_tt); _tt=setTimeout(()=>el.className="",3400);
}

/* ── Field helpers ────────────────────────────────────────── */
function ferr(id,msg){
  $(id).textContent=msg||"";
  const inp=$(id).closest(".field")?.querySelector("input");
  if(inp){inp.classList.toggle("bad",!!msg);inp.classList.toggle("good",!msg&&!!inp.value);}
}
function alert_(id,msg,type="err"){
  const el=$(id); el.textContent=msg||"";
  el.className="alert "+(msg?type+" on":type);
}
function reset(){
  ["l-u-e","l-p-e","r-u-e","r-p-e","r-p2-e"].forEach(id=>ferr(id,""));
  ["l-box","r-box"].forEach(id=>alert_(id,""));
  document.querySelectorAll("#auth-card input").forEach(i=>i.classList.remove("bad","good"));
  $("r-u-icon").textContent="";
  $("sbar").className="sbar"; $("s-lbl").textContent="";
}

/* ── API ──────────────────────────────────────────────────── */
async function api(path,body){
  const r=await fetch("/api"+path,{
    method:"POST",credentials:"include",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify(body)
  });
  return{ok:r.ok,status:r.status,data:await r.json().catch(()=>({}))};
}

/* ── Validation ───────────────────────────────────────────── */
const UN_RE=/^[a-zA-Z][a-zA-Z0-9_-]{2,19}$/;
const RESERVED=new Set(["admin","root","support","system","superuser","administrator","moderator","staff"]);
function clientUN(v){
  if(!v) return"Username is required.";
  if(!UN_RE.test(v)) return"3\u201320 chars, start with a letter, only letters/digits/_ or -.";
  if(RESERVED.has(v.toLowerCase())) return"That username is unavailable. Try another.";
  return null;
}
function clientPW(p){
  if(!p) return"Password is required.";
  if(p.trim().length<8) return"Password must be at least 8 characters.";
  if(!/[A-Z]/.test(p)) return"Must include an uppercase letter.";
  if(!/[a-z]/.test(p)) return"Must include a lowercase letter.";
  if(!/\d/.test(p)) return"Must include a digit.";
  if(!/[^A-Za-z0-9]/.test(p)) return"Must include a special character (!@#$ \u2026).";
  return null;
}

/* ── Username availability ────────────────────────────────── */
let _ud;
$("r-u").addEventListener("input",()=>{
  clearTimeout(_ud);
  const v=$("r-u").value.trim();
  const ce=clientUN(v);
  if(ce){ferr("r-u-e",ce);$("r-u-icon").textContent="";return;}
  ferr("r-u-e",null); $("r-u-icon").textContent="\u23f3";
  _ud=setTimeout(async()=>{
    const{data}=await api("/check-username",{username:v}).catch(()=>({data:{}}));
    ferr("r-u-e",data.valid?null:data.error);
    $("r-u-icon").textContent=data.valid?"\u2705":"\u274c";
  },450);
});

/* ── Password strength ────────────────────────────────────── */
function wireStrength(inputId,barId,lblId){
  let _t;
  $(inputId).addEventListener("input",()=>{
    clearTimeout(_t);
    const p=$(inputId).value;
    if(!p){$(barId).className="sbar";$(lblId).textContent="";return;}
    _t=setTimeout(async()=>{
      const{data}=await api("/check-password",{password:p,username:$("r-u")?.value||""})
        .catch(()=>({data:{}}));
      const s=data.strength||"weak";
      $(barId).className="sbar "+s;
      $(lblId).textContent=s[0].toUpperCase()+s.slice(1);
    },300);
  });
}
wireStrength("r-p","sbar","s-lbl");
wireStrength("rp-new","rp-sbar","rp-lbl");

/* ── Register ─────────────────────────────────────────────── */
$("f-register").addEventListener("submit",async e=>{
  e.preventDefault(); reset();
  const u=$("r-u").value.trim(),p=$("r-p").value,p2=$("r-p2").value;
  let ok=true;
  const ue=clientUN(u); if(ue){ferr("r-u-e",ue);ok=false;}
  const pe=clientPW(p); if(pe){ferr("r-p-e",pe);ok=false;}
  if(p!==p2){ferr("r-p2-e","Passwords do not match.");ok=false;}
  if(!ok) return;
  const btn=$("btn-reg");
  btn.disabled=true; btn.innerHTML='<span class="spin"></span> Creating\u2026';
  const{status,data}=await api("/register",{username:u,password:p})
    .catch(()=>({status:0,data:{error:"Network error."}}));
  btn.disabled=false; btn.textContent="Create Account";
  if(status!==201){alert_("r-box",data.error||"Registration failed.");return;}
  toast("Account created! Please log in.","s");
  $("f-register").reset(); reset();
  tab("login"); $("l-u").value=u;
});

/* ── Login ────────────────────────────────────────────────── */
$("f-login").addEventListener("submit",async e=>{
  e.preventDefault(); reset();
  const u=$("l-u").value.trim(),p=$("l-p").value;
  if(!u){ferr("l-u-e","Username is required.");return;}
  if(!p){ferr("l-p-e","Password is required.");return;}
  const btn=$("btn-login");
  btn.disabled=true; btn.innerHTML='<span class="spin"></span> Logging in\u2026';
  const{ok,data}=await api("/login",{username:u,password:p})
    .catch(()=>({ok:false,data:{error:"Network error."}}));
  btn.disabled=false; btn.textContent="Login";
  if(!ok){alert_("l-box",data.error||"Invalid username or password.");return;}
  curtainOut(()=>{ showDash(data.username); });
  toast("Welcome, "+data.username+"!","s");
});

/* ── Dashboard ────────────────────────────────────────────── */
function showDash(username){
  $("auth-card").classList.add("hidden");
  $("dash-card").classList.remove("hidden");
  $("hdr-name").textContent=username;
  $("hdr-right").classList.remove("hidden");
  $("f-reset").reset(); resetRP();
}
function showAuth(){
  $("auth-card").classList.remove("hidden");
  $("dash-card").classList.add("hidden");
  $("hdr-right").classList.add("hidden");
  $("hdr-name").textContent="";
}
async function logout(){
  curtainOut(async()=>{
    await fetch("/api/logout",{method:"POST",credentials:"include"}).catch(()=>{});
    showAuth(); toast("Logged out.");
  });
}
$("d-logout").addEventListener("click",logout);
$("hdr-logout").addEventListener("click",logout);

/* ── Reset Password ───────────────────────────────────────── */
function resetRP(){
  ["rp-cur-e","rp-new-e","rp-con-e"].forEach(id=>ferr(id,""));
  ["rp-err","rp-ok"].forEach(id=>alert_(id,""));
  document.querySelectorAll("#f-reset input").forEach(i=>i.classList.remove("bad","good"));
  $("rp-sbar").className="sbar"; $("rp-lbl").textContent="";
}
$("f-reset").addEventListener("submit",async e=>{
  e.preventDefault(); resetRP();
  const cur=$("rp-cur").value,nw=$("rp-new").value,con=$("rp-con").value;
  let ok=true;
  if(!cur){ferr("rp-cur-e","Current password is required.");ok=false;}
  const pe=clientPW(nw); if(pe){ferr("rp-new-e",pe);ok=false;}
  if(nw&&nw!==con){ferr("rp-con-e","Passwords do not match.");ok=false;}
  if(!ok) return;
  const btn=$("btn-reset");
  btn.disabled=true; btn.innerHTML='<span class="spin"></span> Updating\u2026';
  const{ok:success,data}=await api("/reset-password",{current:cur,new_pw:nw,confirm:con})
    .catch(()=>({ok:false,data:{error:"Network error."}}));
  btn.disabled=false; btn.textContent="Reset Password";
  if(!success){alert_("rp-err",data.error||"Could not reset password.");return;}
  alert_("rp-ok","Password changed! Redirecting to login\u2026","ok");
  $("f-reset").reset(); resetRP();
  setTimeout(()=>curtainOut(()=>{ showAuth(); toast("Password changed. Please log in.","s"); }),1800);
});

/* ── Auto-login on refresh ────────────────────────────────── */
fetch("/api/me",{credentials:"include"})
  .then(r=>r.ok?r.json():null)
  .then(d=>{ if(d?.username) showDash(d.username); })
  .catch(()=>{});
</script>
</body>
</html>"""


@app.route("/")
def index():
    return PAGE


# ── Start ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import socket
    PORT = 3000

    # Get the machine's LAN IP so the link works from any device on the network
    def get_local_ip():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    HOST = get_local_ip()
    URL  = f"http://{HOST}:{PORT}"

    def _open():
        time.sleep(1.2)
        webbrowser.open(URL)

    threading.Thread(target=_open, daemon=True).start()

    print("\n" + "=" * 52)
    print("  User Authentication -- Login Validator")
    print("=" * 52)
    print(f"  Server URL  :  {URL}")
    print(f"  Local       :  http://localhost:{PORT}")
    print(f"  Users DB    :  {DB_FILE}")
    print(f"  Loaded      :  {len(users)} existing user(s)")
    print("  Ctrl+C to stop")
    print("=" * 52 + "\n")

    # Bind to 0.0.0.0 so the server is reachable on the LAN IP too
    app.run(host="0.0.0.0", port=PORT, debug=False)
