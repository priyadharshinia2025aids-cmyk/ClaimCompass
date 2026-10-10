from __future__ import annotations

import io
import json
import os
import base64
import hashlib
import hmac
import secrets
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")
REPORTS_FILE = BASE_DIR / "storage" / "reports.json"
USERS_FILE = BASE_DIR / "storage" / "users.json"
SERPAPI_URL = "https://serpapi.com/search.json"
TOKEN_TTL_SECONDS = 60 * 60 * 24 * 7

app = FastAPI(title="ClaimCompass API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("FRONTEND_ORIGIN", "http://localhost:5173"), "http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ClaimRequest(BaseModel):
    claim: str = Field(min_length=8, max_length=500)
    search_type: str = Field(default="web", pattern="^(web|news)$")


class SignupRequest(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    email: str = Field(min_length=5, max_length=160)
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: str = Field(min_length=5, max_length=160)
    password: str = Field(min_length=1, max_length=128)


class ForgotPasswordRequest(BaseModel):
    email: str = Field(min_length=5, max_length=160)


class EvidenceItem(BaseModel):
    title: str
    link: str
    snippet: str = ""
    source: str = ""
    published_at: str | None = None
    category: str = "Context"


class Report(BaseModel):
    id: str
    claim: str
    search_type: str
    status: str
    summary: str
    evidence: list[EvidenceItem]
    created_at: str


def read_reports() -> list[dict[str, Any]]:
    if not REPORTS_FILE.exists():
        return []
    try:
        return json.loads(REPORTS_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []


def read_users() -> list[dict[str, Any]]:
    if not USERS_FILE.exists():
        return []
    try:
        return json.loads(USERS_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []


def write_reports(reports: list[dict[str, Any]]) -> None:
    REPORTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    REPORTS_FILE.write_text(json.dumps(reports, indent=2), encoding="utf-8")


def write_users(users: list[dict[str, Any]]) -> None:
    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    USERS_FILE.write_text(json.dumps(users, indent=2), encoding="utf-8")


def normalise_email(email: str) -> str:
    return email.strip().lower()


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 240_000)
    return f"pbkdf2_sha256$240000${base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(digest).decode()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, rounds, salt_text, digest_text = encoded.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.urlsafe_b64decode(salt_text.encode())
        expected = base64.urlsafe_b64decode(digest_text.encode())
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(rounds))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def sign_token(user_id: str) -> str:
    expires = int(time.time()) + TOKEN_TTL_SECONDS
    payload = f"{user_id}.{expires}"
    secret = os.getenv("AUTH_TOKEN_SECRET", "claimcompass-local-development-secret").encode()
    signature = hmac.new(secret, payload.encode(), hashlib.sha256).digest()
    return f"{base64.urlsafe_b64encode(payload.encode()).decode().rstrip('=')}.{base64.urlsafe_b64encode(signature).decode().rstrip('=')}"


def user_from_token(token: str) -> dict[str, Any] | None:
    try:
        payload_text, signature_text = token.split(".")
        payload = base64.urlsafe_b64decode(f"{payload_text}===").decode()
        user_id, expires_text = payload.split(".")
        secret = os.getenv("AUTH_TOKEN_SECRET", "claimcompass-local-development-secret").encode()
        expected = hmac.new(secret, payload.encode(), hashlib.sha256).digest()
        provided = base64.urlsafe_b64decode(f"{signature_text}===")
        if not hmac.compare_digest(expected, provided) or int(expires_text) < int(time.time()):
            return None
    except (ValueError, TypeError, UnicodeDecodeError):
        return None
    if user_id == "demo":
        return {"id": "demo", "name": "Demo Explorer", "email": "demo@claimcompass.local", "is_demo": True}
    return next((user for user in read_users() if user.get("id") == user_id), None)


def current_user(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Sign in to access your ClaimCompass workspace.")
    user = user_from_token(authorization.split(" ", 1)[1].strip())
    if not user:
        raise HTTPException(status_code=401, detail="Your session has expired. Please sign in again.")
    return user


def public_user(user: dict[str, Any]) -> dict[str, Any]:
    return {"id": user["id"], "name": user["name"], "email": user["email"], "is_demo": bool(user.get("is_demo", False))}


def source_name(link: str) -> str:
    try:
        return urlparse(link).netloc.replace("www.", "")
    except ValueError:
        return "Unknown source"


def classify_evidence(title: str, snippet: str) -> str:
    text = f"{title} {snippet}".lower()
    contradicting = ("false", "debunk", "incorrect", "misleading", "no evidence", "wrong")
    supporting = ("study finds", "research shows", "confirmed", "evidence supports", "according to")
    if any(word in text for word in contradicting):
        return "Contradicting"
    if any(word in text for word in supporting):
        return "Supporting"
    return "Context"


async def search_serpapi(request: ClaimRequest) -> list[EvidenceItem]:
    api_key = os.getenv("SERPAPI_API_KEY", "").strip()
    if not api_key or api_key == "your_serpapi_key_here":
        raise HTTPException(status_code=503, detail="SERPAPI_API_KEY is not configured. Add it to backend/.env to run a live search.")
    params = {
        "engine": "google_news" if request.search_type == "news" else "google",
        "q": request.claim,
        "api_key": api_key,
        "num": 8,
    }
    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.get(SERPAPI_URL, params=params)
    if response.status_code != 200:
        raise HTTPException(status_code=502, detail="The search provider returned an error. Please try again.")
    payload = response.json()
    raw_results = payload.get("news_results", []) if request.search_type == "news" else payload.get("organic_results", [])
    evidence: list[EvidenceItem] = []
    for result in raw_results:
        link = result.get("link") or result.get("url")
        title = result.get("title")
        if not link or not title:
            continue
        source = result.get("source")
        source_text = source.get("name", "") if isinstance(source, dict) else (source or source_name(link))
        evidence.append(EvidenceItem(
            title=title,
            link=link,
            snippet=result.get("snippet", ""),
            source=source_text or source_name(link),
            published_at=result.get("date") or result.get("published_at"),
            category=classify_evidence(title, result.get("snippet", "")),
        ))
    return evidence


def build_summary(evidence: list[EvidenceItem]) -> str:
    if not evidence:
        return "No retrievable sources were returned for this search. ClaimCompass cannot verify this claim without evidence."
    counts = {category: sum(item.category == category for item in evidence) for category in ("Supporting", "Contradicting", "Context")}
    parts = [f"Retrieved {len(evidence)} source{'s' if len(evidence) != 1 else ''}."]
    if counts["Supporting"]:
        parts.append(f"{counts['Supporting']} source{'s' if counts['Supporting'] != 1 else ''} contain language that may support the claim.")
    if counts["Contradicting"]:
        parts.append(f"{counts['Contradicting']} source{'s' if counts['Contradicting'] != 1 else ''} contain language that may contradict it.")
    parts.append("This is an evidence map, not a definitive truth score. Read the original sources before deciding.")
    return " ".join(parts)


@app.get("/api/health")
async def health() -> dict[str, bool]:
    return {"ok": True}


@app.post("/api/auth/signup")
async def signup(request: SignupRequest) -> dict[str, Any]:
    email = normalise_email(request.email)
    users = read_users()
    if any(user.get("email") == email for user in users):
        raise HTTPException(status_code=409, detail="An account with this email already exists.")
    user = {
        "id": str(uuid.uuid4()),
        "name": request.name.strip(),
        "email": email,
        "password_hash": hash_password(request.password),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    users.append(user)
    write_users(users)
    return {"token": sign_token(user["id"]), "user": public_user(user)}


@app.post("/api/auth/login")
async def login(request: LoginRequest) -> dict[str, Any]:
    email = normalise_email(request.email)
    user = next((item for item in read_users() if item.get("email") == email), None)
    if not user or not verify_password(request.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Email or password is incorrect.")
    return {"token": sign_token(user["id"]), "user": public_user(user)}


@app.post("/api/auth/demo")
async def demo_login() -> dict[str, Any]:
    user = {"id": "demo", "name": "Demo Explorer", "email": "demo@claimcompass.local", "is_demo": True}
    return {"token": sign_token(user["id"]), "user": public_user(user)}


@app.post("/api/auth/logout")
async def logout(_: dict[str, Any] = Depends(current_user)) -> dict[str, bool]:
    return {"ok": True}


@app.get("/api/auth/me")
async def me(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    return {"user": public_user(user)}


@app.post("/api/auth/forgot-password")
async def forgot_password(request: ForgotPasswordRequest) -> dict[str, str]:
    # Email delivery is intentionally not claimed until a provider is configured.
    return {"message": "If an account exists for that email, reset instructions would be sent. Email delivery is not configured in this local build."}


@app.get("/api/reports", response_model=list[Report])
async def list_reports(user: dict[str, Any] = Depends(current_user)) -> list[dict[str, Any]]:
    return [report for report in read_reports() if report.get("user_id") == user["id"]]


@app.post("/api/reports", response_model=Report)
async def create_report(request: ClaimRequest, user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    evidence = await search_serpapi(request)
    report = Report(
        id=str(uuid.uuid4()),
        claim=request.claim,
        search_type=request.search_type,
        status="insufficient" if not evidence else "review",
        summary=build_summary(evidence),
        evidence=evidence,
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    reports = read_reports()
    report_record = {**report.model_dump(), "user_id": user["id"]}
    reports.insert(0, report_record)
    write_reports(reports[:30])
    return report_record


@app.get("/api/reports/{report_id}/pdf")
async def export_report(report_id: str, user: dict[str, Any] = Depends(current_user)) -> StreamingResponse:
    report = next((item for item in read_reports() if item.get("id") == report_id and item.get("user_id") == user["id"]), None)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    buffer = io.BytesIO()
    document = SimpleDocTemplate(buffer, pagesize=LETTER, rightMargin=48, leftMargin=48, topMargin=48, bottomMargin=48)
    styles = getSampleStyleSheet()
    story = [Paragraph("ClaimCompass Evidence Report", styles["Title"]), Spacer(1, 12), Paragraph(f"<b>Claim:</b> {report['claim']}", styles["BodyText"]), Spacer(1, 8), Paragraph(report["summary"], styles["BodyText"]), Spacer(1, 16)]
    for item in report["evidence"]:
        story.extend([Paragraph(f"<b>{item['category']}</b> | {item['source']}", styles["Heading3"]), Paragraph(item["title"], styles["BodyText"]), Paragraph(item.get("snippet", ""), styles["BodyText"]), Paragraph(item["link"], styles["BodyText"]), Spacer(1, 12)])
    document.build(story)
    buffer.seek(0)
    return StreamingResponse(buffer, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="claimcompass-{report_id}.pdf"'})
