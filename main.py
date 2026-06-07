from pathlib import Path
from dotenv import load_dotenv
load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env")

import os
import time
import hmac
import hashlib
import secrets
import json
import threading
import tempfile
from urllib.parse import urlencode
from typing import Dict, Optional

import requests as http_requests
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

# ═══════════════════════════════════════════════════════════════════════════
# КОНФИГУРАЦИЯ
# ═══════════════════════════════════════════════════════════════════════════
GOOGLE_CLIENT_ID     = os.getenv("GOOGLE_CLIENT_ID", "").strip()
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()
GOOGLE_REDIRECT_URI  = os.getenv(
    "GOOGLE_REDIRECT_URI",
    "https://youtubelocalizer.com/v1/youtube/oauth-callback"
).strip()

LEMONSQUEEZY_API_KEY    = os.getenv("LEMONSQUEEZY_API_KEY", "").strip()
LEMONSQUEEZY_STORE_URL  = os.getenv("LEMONSQUEEZY_STORE_URL", "").strip()
LEMON_WEBHOOK_SECRET    = os.getenv("LEMON_WEBHOOK_SECRET", "").strip()
LEMON_STORE_ID          = os.getenv("LEMON_STORE_ID", "").strip()

YT_SCOPES = " ".join([
    "https://www.googleapis.com/auth/youtube.force-ssl",
    "https://www.googleapis.com/auth/userinfo.email",
    "openid",
])

# Маппинг variant_id → план (заполни своими ID из LS)
PLAN_BY_VARIANT: dict[str, str] = {
    # "123456": "basic",
    # "123457": "pro",
}

app = FastAPI(title="YouTube Localizer Server", version="2.4")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ═══════════════════════════════════════════════════════════════════════════
# ФАЙЛОВОЕ ХРАНИЛИЩЕ СЕССИЙ (атомарная запись, работает на Render)
# ═══════════════════════════════════════════════════════════════════════════
SESSION_FILE = Path("/tmp/yt_oauth_sessions.json")
SESSION_TTL  = 600
_session_lock = threading.Lock()

def _read_sessions() -> dict:
    with _session_lock:
        try:
            if not SESSION_FILE.exists():
                return {}
            raw = SESSION_FILE.read_text(encoding='utf-8')
            if not raw.strip():
                return {}
            data = json.loads(raw)
            now = time.time()
            return {k: v for k, v in data.items()
                    if now - v.get("created", 0) < SESSION_TTL}
        except Exception:
            return {}

def _write_sessions(sessions: dict):
    with _session_lock:
        try:
            tmp_fd, tmp_path = tempfile.mkstemp(
                dir=SESSION_FILE.parent,
                prefix='.tmp_sessions_', suffix='.json'
            )
            with os.fdopen(tmp_fd, 'w', encoding='utf-8') as f:
                json.dump(sessions, f, ensure_ascii=False)
            os.replace(tmp_path, SESSION_FILE)
        except Exception as e:
            print(f"[SESSION] Write error: {e}")

def _get_session(state: str) -> Optional[dict]:
    return _read_sessions().get(state)

def _set_session(state: str, data: dict):
    sessions = _read_sessions()
    sessions[state] = data
    _write_sessions(sessions)

def _delete_session(state: str):
    sessions = _read_sessions()
    sessions.pop(state, None)
    _write_sessions(sessions)

# ═══════════════════════════════════════════════════════════════════════════
# LEMON SQUEEZY — вспомогательные функции
# ═══════════════════════════════════════════════════════════════════════════
def _ls_headers() -> dict:
    return {
        "Accept": "application/vnd.api+json",
        "Authorization": f"Bearer {LEMONSQUEEZY_API_KEY}",
    }

def _plan_from_variant(variant_id: str, variant_name: str = "") -> str:
    if variant_id in PLAN_BY_VARIANT:
        return PLAN_BY_VARIANT[variant_id]
    name = variant_name.lower()
    if "pro" in name:
        return "pro"
    if "advanced" in name or "adv" in name:
        return "advanced"
    return "basic"

def ls_activate(license_key: str, instance_name: str) -> dict:
    """Активация лицензии через Lemon Squeezy API"""
    if not LEMONSQUEEZY_API_KEY:
        return {
            "ok": True, "plan": "basic",
            "customer_email": "test@example.com",
            "variant_name": "Basic", "variant_id": "",
            "instance_id": secrets.token_hex(16), "expires_at": None,
        }
    try:
        resp = http_requests.post(
            "https://api.lemonsqueezy.com/v1/licenses/activate",
            headers=_ls_headers(),
            params={
                "license_key": license_key,
                "instance_name": instance_name or "VidLocalizer",
            },
            timeout=20,
        )
        data = resp.json()
        if resp.status_code not in (200, 201):
            return {"ok": False, "reason": data.get("error") or f"HTTP {resp.status_code}"}

        meta          = data.get("meta", {})
        key_info      = data.get("license_key", {})
        instance_info = data.get("instance", {})
        variant_id    = str(meta.get("variant_id", ""))
        variant_name  = meta.get("variant_name", "")

        return {
            "ok": True,
            "plan": _plan_from_variant(variant_id, variant_name),
            "customer_email": meta.get("customer_email", ""),
            "variant_name": variant_name,
            "variant_id": variant_id,
            "instance_id": str(instance_info.get("id", secrets.token_hex(16))),
            "expires_at": key_info.get("expires_at"),
            "activation_limit": key_info.get("activation_limit"),
            "activation_usage": key_info.get("activation_usage"),
        }
    except Exception as e:
        return {"ok": False, "reason": str(e)}

def ls_validate(license_key: str, instance_id: str = "") -> dict:
    """Валидация лицензии через Lemon Squeezy API"""
    if not LEMONSQUEEZY_API_KEY:
        return {"ok": True, "plan": "basic", "customer_email": "test@example.com", "expires_at": None}
    try:
        params = {"license_key": license_key}
        if instance_id:
            params["instance_id"] = instance_id

        resp = http_requests.post(
            "https://api.lemonsqueezy.com/v1/licenses/validate",
            headers=_ls_headers(),
            params=params,
            timeout=20,
        )
        data = resp.json()
        if resp.status_code != 200:
            return {"ok": False, "reason": data.get("error", f"HTTP {resp.status_code}")}

        meta       = data.get("meta", {})
        key_info   = data.get("license_key", {})
        variant_id = str(meta.get("variant_id", ""))
        variant_name = meta.get("variant_name", "")

        return {
            "ok": data.get("valid", False),
            "plan": _plan_from_variant(variant_id, variant_name),
            "customer_email": meta.get("customer_email", ""),
            "variant_name": variant_name,
            "variant_id": variant_id,
            "expires_at": key_info.get("expires_at"),
            "status": key_info.get("status"),
        }
    except Exception as e:
        return {"ok": False, "reason": str(e)}

def _verify_webhook_signature(body: bytes, signature: str, secret: str) -> bool:
    """
    Проверка подписи вебхука от Lemon Squeezy.
    LS подписывает тело запроса через HMAC-SHA256.
    Подпись передаётся в заголовке X-Signature.
    """
    if not secret:
        print("[WEBHOOK] WARNING: LEMON_WEBHOOK_SECRET not set, skipping signature check")
        return True
    expected = hmac.new(
        secret.encode("utf-8"),
        body,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)

def _clean(payload: dict) -> dict:
    return {k: v for k, v in payload.items() if k not in {"sig", "nonce", "ts"}}

# ═══════════════════════════════════════════════════════════════════════════
# БАЗОВЫЕ ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════
@app.get("/")
async def root():
    return {
        "service": "VidLocalizer Server",
        "version": "2.4",
        "google_configured": bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET),
        "ls_configured": bool(LEMONSQUEEZY_API_KEY),
        "webhook_secret_set": bool(LEMON_WEBHOOK_SECRET),
    }

@app.get("/health")
@app.get("/v1/health")
async def health():
    return {
        "status": "healthy",
        "version": "2.4",
        "google_oauth_ready": bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET),
        "ls_ready": bool(LEMONSQUEEZY_API_KEY),
        "webhook_ready": bool(LEMON_WEBHOOK_SECRET),
        "active_sessions": len(_read_sessions()),
    }

# ═══════════════════════════════════════════════════════════════════════════
# LEMON SQUEEZY WEBHOOK  ← ГЛАВНЫЙ ФИХ
# ═══════════════════════════════════════════════════════════════════════════
@app.post("/webhook/lemon")
async def lemon_webhook(request: Request):
    """
    Принимает вебхуки от Lemon Squeezy.
    URL в LS: https://yt-license-api-2v6d.onrender.com/webhook/lemon
    Подписанные события: subscription_created, subscription_updated,
                         subscription_cancelled, subscription_expired
    """
    body = await request.body()

    # Проверяем подпись
    signature = request.headers.get("X-Signature", "")
    if not _verify_webhook_signature(body, signature, LEMON_WEBHOOK_SECRET):
        print(f"[WEBHOOK] Invalid signature! sig={signature[:20]}...")
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    try:
        payload = json.loads(body)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    event_name = payload.get("meta", {}).get("event_name", "unknown")
    print(f"[WEBHOOK] Received event: {event_name}")

    # ── subscription_created ──────────────────────────────────────────────
    if event_name == "subscription_created":
        sub = payload.get("data", {}).get("attributes", {})
        customer_email = sub.get("user_email", "")
        status         = sub.get("status", "")
        variant_name   = sub.get("variant_name", "")
        variant_id     = str(payload.get("data", {}).get("relationships", {})
                             .get("variant", {}).get("data", {}).get("id", ""))
        plan = _plan_from_variant(variant_id, variant_name)

        print(f"[WEBHOOK] subscription_created: email={customer_email} plan={plan} status={status}")
        # Здесь можно сохранить в БД: активировать подписку для email
        return {"received": True, "event": event_name, "plan": plan, "email": customer_email}

    # ── subscription_updated ──────────────────────────────────────────────
    elif event_name == "subscription_updated":
        sub    = payload.get("data", {}).get("attributes", {})
        status = sub.get("status", "")
        email  = sub.get("user_email", "")
        print(f"[WEBHOOK] subscription_updated: email={email} status={status}")
        # active | past_due | paused | cancelled | expired
        return {"received": True, "event": event_name, "status": status, "email": email}

    # ── subscription_cancelled ────────────────────────────────────────────
    elif event_name == "subscription_cancelled":
        sub   = payload.get("data", {}).get("attributes", {})
        email = sub.get("user_email", "")
        ends_at = sub.get("ends_at", "")
        print(f"[WEBHOOK] subscription_cancelled: email={email} ends_at={ends_at}")
        # Подписка ещё действует до ends_at, после — истекает
        return {"received": True, "event": event_name, "email": email, "ends_at": ends_at}

    # ── subscription_expired ──────────────────────────────────────────────
    elif event_name == "subscription_expired":
        sub   = payload.get("data", {}).get("attributes", {})
        email = sub.get("user_email", "")
        print(f"[WEBHOOK] subscription_expired: email={email}")
        return {"received": True, "event": event_name, "email": email}

    # ── Все остальные события ─────────────────────────────────────────────
    else:
        print(f"[WEBHOOK] Unhandled event: {event_name}")
        return {"received": True, "event": event_name}

# ═══════════════════════════════════════════════════════════════════════════
# LICENSE ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════
@app.get("/v1/license/store-url")
async def get_store_url():
    if not LEMONSQUEEZY_STORE_URL:
        raise HTTPException(500, "Store URL not configured")
    return {"store_url": LEMONSQUEEZY_STORE_URL}

@app.post("/v1/license/activate")
async def activate_license(payload: dict):
    fields      = _clean(payload)
    license_key = fields.get("license_key", "").strip()
    hwid        = fields.get("hwid", "").strip()
    instance    = fields.get("instance", "") or hwid or "VidLocalizer"

    if not license_key:
        raise HTTPException(400, "Missing license_key")
    if not hwid:
        raise HTTPException(400, "Missing hwid")

    result = ls_activate(license_key, instance_name=instance)
    if not result.get("ok"):
        return {"activated": False, "reason": result.get("reason", "License activation failed")}

    return {
        "activated": True,
        "status": "active",
        "instance_id": result.get("instance_id"),
        "expires_at": result.get("expires_at"),
        "meta": {
            "plan": result["plan"],
            "customer_email": result["customer_email"],
            "product_name": "VidLocalizer",
            "variant_name": result.get("variant_name", ""),
            "variant_id": result.get("variant_id", ""),
        },
    }

@app.post("/v1/license/validate")
async def validate_license(payload: dict):
    fields      = _clean(payload)
    license_key = fields.get("license_key", "").strip()
    # Принимаем и instance_id и hwid для обратной совместимости
    instance_id = fields.get("instance_id", "").strip() or fields.get("hwid", "").strip()

    if not license_key:
        return {"valid": False, "reason": "no_key"}

    result = ls_validate(license_key, instance_id=instance_id)
    return {
        "valid": result.get("ok", False),
        "status": result.get("status", "unknown"),
        "expires_at": result.get("expires_at"),
        "reason": result.get("reason"),
        "meta": {
            "plan": result.get("plan", "basic"),
            "customer_email": result.get("customer_email", ""),
            "variant_name": result.get("variant_name", ""),
        },
    }

@app.get("/v1/license/check")
async def check_license_get(license_key: str = ""):
    if not license_key:
        return {"active": False, "reason": "no_key"}
    result = ls_validate(license_key)
    return {"active": result.get("ok", False), "data": result}

@app.post("/v1/license/transfer")
async def transfer_license(payload: dict):
    fields      = _clean(payload)
    license_key = fields.get("license_key", "").strip()
    if not license_key:
        raise HTTPException(400, "Missing license_key")
    result = ls_validate(license_key)
    return {"transferred": result.get("ok", False), "data": result}

# ═══════════════════════════════════════════════════════════════════════════
# YOUTUBE OAUTH
# ═══════════════════════════════════════════════════════════════════════════
@app.get("/v1/youtube/auth-url")
async def get_youtube_auth_url():
    if not GOOGLE_CLIENT_ID:
        raise HTTPException(500, "GOOGLE_CLIENT_ID not configured")
    state = secrets.token_urlsafe(32)
    _set_session(state, {"created": time.time(), "tokens": None, "user_info": None, "error": None})
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": YT_SCOPES,
        "access_type": "offline",
        "include_granted_scopes": "true",
        "prompt": "consent",
        "state": state,
    }
    auth_url = "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)
    return {"auth_url": auth_url, "state": state}

@app.get("/v1/youtube/oauth-callback")
async def oauth_callback(code: str = "", state: str = "", error: str = ""):
    session = _get_session(state)
    if not session:
        return HTMLResponse("<h2 style='color:red;font-family:sans-serif;text-align:center;padding:60px'>❌ Invalid or expired session</h2>", status_code=400)

    if error:
        session["error"] = error
        _set_session(state, session)
        return HTMLResponse(f"<h2 style='color:red;font-family:sans-serif;text-align:center;padding:60px'>❌ Google error: {error}</h2>")

    if not code:
        session["error"] = "no_code"
        _set_session(state, session)
        return HTMLResponse("<h2>❌ No authorization code</h2>", status_code=400)

    try:
        token_resp = http_requests.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code": code,
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uri": GOOGLE_REDIRECT_URI,
                "grant_type": "authorization_code",
            },
            timeout=20,
        )
        tokens = token_resp.json()

        if "error" in tokens or "access_token" not in tokens:
            err = tokens.get("error_description") or tokens.get("error") or "unknown"
            session["error"] = err
            _set_session(state, session)
            return HTMLResponse(f"<h2 style='color:red;font-family:sans-serif;text-align:center;padding:60px'>❌ Token error: {err}</h2>", status_code=400)

        user_info = {}
        try:
            ui = http_requests.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {tokens['access_token']}"},
                timeout=10,
            )
            if ui.ok:
                user_info = ui.json()
        except Exception:
            pass

        session["tokens"]    = tokens
        session["user_info"] = user_info
        _set_session(state, session)
        email = user_info.get("email", "—")

        close_script = "<script>setTimeout(function(){try{window.close();}catch(e){}}, 2500);</script>"
        return HTMLResponse(f"""
        <html><head><title>Authorized</title></head>
        <body style="font-family:sans-serif;background:#0b0d14;color:#eef0fa;text-align:center;padding:80px">
          <div style="display:inline-block;background:#1f2333;padding:40px 60px;border-radius:12px;border:1px solid #3ddc84">
            <h1 style="color:#3ddc84;margin:0 0 16px">✅ Authorization Successful</h1>
            <p style="font-size:18px">Signed in as <b style="color:#fff">{email}</b></p>
            <p style="color:#8088a8;margin-top:20px">You may close this window and return to the application.</p>
          </div>
          {close_script}
        </body></html>
        """)
    except Exception as e:
        session["error"] = str(e)
        _set_session(state, session)
        return HTMLResponse(f"<h2>❌ Server error: {e}</h2>", status_code=500)

@app.get("/v1/youtube/check-auth")
async def check_auth(state: str):
    session = _get_session(state)
    if not session:
        return {"status": "expired"}
    if session.get("error"):
        err = session["error"]
        _delete_session(state)
        return {"status": "error", "error": err}
    if session.get("tokens"):
        result = {"status": "success", "tokens": session["tokens"], "user_info": session["user_info"] or {}}
        _delete_session(state)
        return result
    return {"status": "pending"}

@app.post("/v1/youtube/refresh-token")
async def refresh_token(payload: dict):
    rt = payload.get("refresh_token", "").strip()
    if not rt:
        raise HTTPException(400, "Missing refresh_token")
    try:
        r = http_requests.post(
            "https://oauth2.googleapis.com/token",
            data={
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "refresh_token": rt,
                "grant_type": "refresh_token",
            },
            timeout=15,
        )
        data = r.json()
        if "error" in data:
            raise HTTPException(401, data.get("error_description", data["error"]))
        return data
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(502, str(e))

@app.post("/v1/youtube/revoke")
async def revoke_token(payload: dict):
    token = payload.get("refresh_token") or payload.get("access_token") or ""
    if not token:
        raise HTTPException(400, "Missing token")
    try:
        http_requests.post("https://oauth2.googleapis.com/revoke", params={"token": token}, timeout=10)
        return {"revoked": True}
    except Exception as e:
        return {"revoked": False, "error": str(e)}

# ═══════════════════════════════════════════════════════════════════════════
# TRANSLATION
# ═══════════════════════════════════════════════════════════════════════════
@app.post("/v1/translate")
async def translate(payload: dict):
    text   = payload.get("text", "")
    source = payload.get("source_lang", "auto")
    target = payload.get("target_lang", "en")
    try:
        from deep_translator import GoogleTranslator
        translated = GoogleTranslator(source=source, target=target).translate(text)
        return {"translated_text": translated or text, "target_lang": target}
    except Exception as e:
        return {"translated_text": text, "error": str(e)}

@app.post("/v1/usage/check")
async def usage_check(payload: dict):
    return {"allowed": True, "remaining": 999}

@app.post("/v1/usage/increment")
async def usage_increment(payload: dict):
    return {"ok": True}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
