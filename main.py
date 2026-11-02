
import os
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Request, Form
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pwdlib import PasswordHash
from sqlalchemy import (
    create_engine, String, Text, Integer,
    DateTime, func, select
)
from sqlalchemy.orm import (
    DeclarativeBase, Mapped, mapped_column,
    sessionmaker
)
from starlette.middleware.sessions import SessionMiddleware

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
DATABASE_URL = os.getenv("DATABASE_URL")
SESSION_SECRET = os.getenv("SESSION_SECRET")

if not DATABASE_URL or not SESSION_SECRET:
    raise RuntimeError("Set DATABASE_URL and SESSION_SECRET in .env")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine)
password_hash = PasswordHash.recommended()


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(100), unique=True)
    email: Mapped[str] = mapped_column(String(255), unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    created_at: Mapped[object] = mapped_column(
        DateTime, server_default=func.now()
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Convenient for a student project.
    # Use database migrations for a production deployment.
    Base.metadata.create_all(engine)
    yield


app = FastAPI(title="Fertility & Economic Growth")
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    same_site="lax",
    https_only=os.getenv("COOKIE_HTTPS_ONLY", "false").lower() == "true",
    max_age=3600,
)

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app.mount(
    "/static",
    StaticFiles(directory=str(BASE_DIR / "static")),
    name="static",
)


@app.get("/")
def home(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse("/dashboard", status_code=303)
    return RedirectResponse("/login", status_code=303)


@app.get("/register")
def register_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="register.html",
        context={"error": None},
    )


@app.post("/register")
def register(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
):
    username = username.strip()
    email = email.strip().lower()

    if not username or len(username) > 100:
        return templates.TemplateResponse(
            request=request, name="register.html",
            context={"error": "Enter a valid username."},
            status_code=400,
        )

    if len(email) > 255 or "@" not in email:
        return templates.TemplateResponse(
            request=request, name="register.html",
            context={"error": "Enter a valid email address."},
            status_code=400,
        )

    if len(password) < 10 or len(password) > 128:
        return templates.TemplateResponse(
            request=request, name="register.html",
            context={"error": "Password must be 10–128 characters."},
            status_code=400,
        )

    with SessionLocal() as db:
        existing = db.scalar(
            select(User).where(
                (User.username == username) | (User.email == email)
            )
        )

        if existing:
            return templates.TemplateResponse(
                request=request, name="register.html",
                context={"error": "Username or email is already registered."},
                status_code=400,
            )

        user = User(
            username=username,
            email=email,
            password_hash=password_hash.hash(password),
        )
        db.add(user)
        db.commit()

    return RedirectResponse("/login?registered=1", status_code=303)


@app.get("/login")
def login_page(request: Request, registered: int = 0):
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"error": None, "registered": registered == 1},
    )


@app.post("/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    username = username.strip()

    with SessionLocal() as db:
        user = db.scalar(
            select(User).where(
                (User.username == username) |
                (User.email == username.lower())
            )
        )

        if not user or not password_hash.verify(
            password, user.password_hash
        ):
            return templates.TemplateResponse(
                request=request,
                name="login.html",
                context={
                    "error": "Invalid username/email or password.",
                    "registered": False,
                },
                status_code=401,
            )

        user_id = user.id
        display_name = user.username

    # Discard any previous session contents before logging in.
    request.session.clear()
    request.session["user_id"] = user_id

    return RedirectResponse("/dashboard", status_code=303)


@app.get("/dashboard")
def dashboard(request: Request):
    user_id = request.session.get("user_id")

    if not user_id:
        return RedirectResponse("/login", status_code=303)

    with SessionLocal() as db:
        user = db.get(User, user_id)

        if not user:
            request.session.clear()
            return RedirectResponse("/login", status_code=303)

        username = user.username

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={"username": username},
    )


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)
