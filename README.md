# User Authentication — Login & Password Validator

A single-file Python web app that handles user registration, login, password reset, and credential validation — built from the [PRD.md](./PRD.md) requirements.

---

## Project Structure

```
Loging Validation/
├── run.py          ← entire app (backend + frontend in one file)
├── users.json      ← auto-created when first user registers
├── PRD.md          ← original product requirements document
└── README.md       ← this file
```

---

## Requirements

- **Python 3.8 or higher**
- **pip** (comes with Python)

Check your Python version:

```bash
python --version
```

---

## Step 1 — Install Dependencies

Open a terminal in the project folder and run:

```bash
pip install flask flask-cors bcrypt
```

That's all you need. No other packages required.

---

## Step 2 — Run the App

```bash
python run.py
```

The browser will **open automatically** at:

```
http://localhost:3000
```

Terminal output will look like this:

```
====================================================
  User Authentication -- Login Validator
====================================================
  Server URL  :  http://192.168.x.x:3000
  Local       :  http://localhost:3000
  Users DB    :  /path/to/users.json
  Loaded      :  0 existing user(s)
  Ctrl+C to stop
====================================================
```

---

## Step 3 — Using the App

### Register
1. Click the **Register** tab
2. Enter a username (3–20 chars, must start with a letter)
3. Enter a password (min 8 chars, must include uppercase, lowercase, digit, and special character)
4. Confirm the password
5. Click **Create Account**

### Login
1. Enter your registered username and password
2. Click **Login**
3. On success you are taken to the dashboard

### Dashboard (after login)
After logging in you will see two options only:

- **Reset Password** — change your current password
- **Logout** — end your session

### Reset Password
1. Enter your current password
2. Enter a new password (same rules apply)
3. Confirm the new password
4. Click **Reset Password**
5. You are automatically logged out and redirected to the login page

### Logout
Click the **Logout** button on the dashboard or the header.

---

## Step 4 — Stop the Server

Press `Ctrl+C` in the terminal.

---

## User Data

Registered users are saved to **`users.json`** in the same folder as `run.py`.

```json
{
  "johndoe": {
    "username": "johndoe",
    "password_hash": "$2b$12$..."
  }
}
```

- Passwords are **never stored in plain text** — only bcrypt hashes
- The file is created automatically on first registration
- Delete `users.json` to reset all accounts

---

## Password Rules

| Rule | Requirement |
|---|---|
| Minimum length | 8 characters |
| Maximum length | 128 characters |
| Uppercase letter | At least one (A–Z) |
| Lowercase letter | At least one (a–z) |
| Digit | At least one (0–9) |
| Special character | At least one (!@#$%^&* etc.) |
| Common passwords | Rejected outright |
| Similar to username | Not allowed |

## Username Rules

| Rule | Requirement |
|---|---|
| Length | 3–20 characters |
| Allowed characters | Letters, digits, underscore `_`, hyphen `-` |
| Starting character | Must start with a letter |
| Reserved names | admin, root, support, system, etc. are blocked |

---

## Security Features

- **bcrypt hashing** — passwords hashed with work factor 12 (one-way, salted)
- **Timing-safe login** — same response time whether username exists or not
- **Account lockout** — 5 failed attempts triggers a 15-minute lockout
- **Generic error messages** — never reveals which field is wrong
- **HttpOnly session cookies** — session tokens inaccessible to JavaScript
- **Session expiry** — sessions expire after 30 minutes of inactivity
- **All sessions revoked** on password reset

---

## Access from Another Device (same network)

The server also binds on your local IP. Check the terminal for the `Server URL` line:

```
Server URL  :  http://192.168.1.x:3000
```

Open that URL on any phone or device connected to the same Wi-Fi.

---

## Troubleshooting

| Problem | Solution |
|---|---|
| `ModuleNotFoundError: flask` | Run `pip install flask flask-cors bcrypt` |
| `Address already in use` | Another process is using port 3000 — close it or change the `PORT` variable in `run.py` |
| Browser doesn't open | Manually visit `http://localhost:3000` |
| Forgot password | Delete `users.json` and register again (no email reset in this version) |
| Want to clear all users | Delete `users.json` — it will be recreated on next registration |
