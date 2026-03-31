# ---------------------------------------------------------------------------
# routers/auth.py
# Handles user registration and login.
# Also exposes get_current_user() as a shared helper used by other routers
# to validate the JWT token on protected endpoints.
# ---------------------------------------------------------------------------

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
from database import get_db
from models import User
from pydantic import BaseModel
import os

router = APIRouter()

# ---------------------------------------------------------------------------
# Password hashing
# Uses bcrypt, which is a slow, salted hashing algorithm designed to be
# resistant to brute-force attacks. Never store plain-text passwords.
# ---------------------------------------------------------------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ---------------------------------------------------------------------------
# JWT configuration
# SECRET_KEY signs the token — keep it secret and set it via the environment.
# Tokens expire after 24 hours, after which the user must log in again.
# ---------------------------------------------------------------------------
SECRET_KEY = os.getenv("SECRET_KEY", "fallbacksecretkey")
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 24


# ---------------------------------------------------------------------------
# Request schemas (validated automatically by FastAPI via Pydantic)
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    """Returns a bcrypt hash of the given plain-text password."""
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    """Returns True if the plain-text password matches the stored hash."""
    return pwd_context.verify(plain, hashed)


def create_token(username: str) -> str:
    """
    Creates a signed JWT token for the given username.

    The token contains:
        sub - the username (subject)
        exp - the expiry timestamp (24 hours from now)
    """
    expires = datetime.utcnow() + timedelta(hours=TOKEN_EXPIRE_HOURS)
    payload = {"sub": username, "exp": expires}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token: str, db: Session) -> User:
    """
    Decodes and validates a JWT token, then returns the matching User.

    Called by upload.py and analyze.py to protect their endpoints.
    Raises HTTP 401 if the token is invalid, expired, or the user is not found.

    Args:
        token: Raw JWT string (without the "Bearer " prefix).
        db:    Active database session.

    Returns:
        The User object for the authenticated user.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/register")
def register(request: RegisterRequest, db: Session = Depends(get_db)):
    """
    Creates a new user account.

    Steps:
        1. Check that the username is not already taken.
        2. Hash the password and save the new User to the database.
        3. Return a JWT token so the user is immediately logged in.
    """
    # Reject the request if the username already exists
    existing = db.query(User).filter(User.username == request.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already taken")

    # Create and persist the new user with a hashed password
    user = User(
        username=request.username,
        password_hash=hash_password(request.password)
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # Issue a token so the frontend can immediately make authenticated requests
    token = create_token(user.username)
    return {"token": token, "username": user.username}


@router.post("/login")
def login(request: LoginRequest, db: Session = Depends(get_db)):
    """
    Authenticates an existing user and returns a JWT token.

    Returns HTTP 401 if the username doesn't exist or the password is wrong.
    We intentionally use the same error message for both cases to avoid
    leaking information about which usernames exist.
    """
    user = db.query(User).filter(User.username == request.username).first()

    # Verify the user exists and the password matches the stored hash
    if not user or not verify_password(request.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_token(user.username)
    return {"token": token, "username": user.username}
