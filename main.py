import os
import logging
import sqlite3
import secrets
from typing import Optional
from uuid import uuid4

from fastapi import Cookie, Depends, FastAPI, HTTPException, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import HTMLResponse, RedirectResponse

app = FastAPI()
security = HTTPBasic()

# Credentials and session secret — override via environment variables in production
USERNAME = os.environ["AUTH_USERNAME"]
PASSWORD = os.environ["AUTH_PASSWORD"]
SESSION_SECRET = uuid4().hex
COOKIE_NAME = "session_token"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


def html(status: Literal["ok", "warn", "err", "info"], content: str) -> str:
    """Helper function to create an HTML response."""
    color = {
        "ok": "#66ff66",
        "warn": "#ffff66",
        "err": "#ff6666",
        "info": "#ccffff",
    }.get(status, "#ffffff")

    return f"""
        <html>
            <body bgcolor='{color}'>
                <h1>{content}</h1>
            </body>
        </html>
    """


@app.get("/auth", response_class=HTMLResponse)
def authenticate(
    credentials: HTTPBasicCredentials = Depends(security),
):
    """Basic-Auth protected endpoint. Sets a session cookie on success."""
    is_user_ok = secrets.compare_digest(
        credentials.username.encode(), USERNAME.encode()
    )
    is_pass_ok = secrets.compare_digest(
        credentials.password.encode(), PASSWORD.encode()
    )

    if not (is_user_ok and is_pass_ok):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

    response = HTMLResponse(content=html("info", "Authentication successful!"))
    response.set_cookie(
        key=COOKIE_NAME,
        value=SESSION_SECRET,
        httponly=True,
        samesite="lax",
        secure=True,
        max_age=3 * 3600,  # 3 hours
        path="/",
    )
    return response


@app.get("/register/{uid}")
def register(
    uid: str,
    credentials: HTTPBasicCredentials = Depends(security),
):
    """Basic-Auth protected registration. Sets a session cookie on success."""
    is_user_ok = secrets.compare_digest(
        credentials.username.encode(), USERNAME.encode()
    )
    is_pass_ok = secrets.compare_digest(
        credentials.password.encode(), PASSWORD.encode()
    )

    if not (is_user_ok and is_pass_ok):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

    with sqlite3.connect("data.db") as conn:
        conn.execute("""
                    CREATE TABLE IF NOT EXISTS qr_codes (
                        uid TEXT PRIMARY KEY, 
                        counter INTEGER DEFAULT 0,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                     )""")
        conn.execute("INSERT INTO qr_codes (uid) VALUES (?)", (uid,))
        conn.commit()


@app.get("/qr/{uid}", response_class=HTMLResponse)
def qr(uid: str, session_token: Optional[str] = Cookie(default=None)):
    """Cookie-protected endpoint. No auth header required — validates the session cookie."""
    if not session_token or not secrets.compare_digest(session_token, SESSION_SECRET):
        logging.warning("Unauthorized access attempt to /qr/%s", uid)
        return RedirectResponse(url="/auth", status_code=302)

    with sqlite3.connect("data.db") as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT uid, timestamp, counter FROM qr_codes WHERE uid = ?", (uid,)
        )
        rows = cursor.fetchall()
        if len(rows) == 0:
            return HTMLResponse(content=html("err", "Invalid QR code!"))

        for uid, timestamp, counter in rows:
            cursor.execute(
                "UPDATE qr_codes SET counter = ? + 1 WHERE uid = ?", (counter, uid)
            )
            cursor.execute(
                "UPDATE qr_codes SET timestamp = CURRENT_TIMESTAMP WHERE uid = ?",
                (uid,),
            )
            conn.commit()

            if counter > 0:
                return HTMLResponse(
                    content=html(
                        "warn",
                        f"Pass {uid} has been used already {counter} times! Latest use: {timestamp}",
                    )
                )

    return HTMLResponse(content=html("ok", "QR code is valid!"))
