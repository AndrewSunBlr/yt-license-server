#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
YouTube Localizer License Server v3.0
- Получение лицензионного ключа через API Lemon Squeezy
"""

import os
import json
import time
import hmac
import hashlib
import secrets
import requests
from datetime import datetime, timedelta
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String, Integer, DateTime, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import uvicorn

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# ═══════════════════════════════════════════════════════════════════════════
# КОНФИГУРАЦИЯ
# ═══════════════════════════════════════════════════════════════════════════

SERVER_PRIVATE_KEY_HEX = os.environ.get("SERVER_PRIVATE_KEY", "")
APP_SHARED_SECRET = os.environ.get("APP_SHARED_SECRET", "")
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://localhost/yt_licenses")
LEMON_WEBHOOK_SECRET = os.environ.get("LEMON_WEBHOOK_SECRET", "")
LEMON_API_KEY = os.environ.get("LEMON_API_KEY", "")
LEMON_STORE_ID = os.environ.get("LEMON_STORE_ID", "")

# Генерация или загрузка ключей
SERVER_PUBLIC_KEY_HEX = ""
if SERVER_PRIVATE_KEY_HEX and HAS_CRYPTO:
    try:
        private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SERVER_PRIVATE_KEY_HEX))
        SERVER_PUBLIC_KEY_HEX = private_key.public_key().public_bytes_raw().hex()
        print(f"[✓] Public key loaded from SERVER_PRIVATE_KEY")
    except Exception as e:
        print(f"[!] Error loading private key: {e}")
        private_key = Ed25519PrivateKey.generate()
        SERVER_PRIVATE_KEY_HEX = private_key.private_bytes_raw().hex()
        SERVER_PUBLIC_KEY_HEX = private_key.public_key().public_bytes_raw().hex()
        print(f"[!] Generated new key pair")
else:
    private_key = Ed25519PrivateKey.generate()
    SERVER_PRIVATE_KEY_HEX = private_key.private_bytes_raw().hex()
    SERVER_PUBLIC_KEY_HEX = private_key.public_key().public_bytes_raw().hex()
    print(f"[!] Generated new key pair")

print(f"[✓] Public key: {SERVER_PUBLIC_KEY_HEX[:32]}...")
print(f"[✓] Shared secret available: {bool(APP_SHARED_SECRET)}")
print(f"[✓] Lemon webhook secret available: {bool(LEMON_WEBHOOK_SECRET)}")
print(f"[✓] Lemon API key available: {bool(LEMON_API_KEY)}")

# ─── Database ─────────────────────────────────────────────────────────────────
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ═══════════════════════════════════════════════════════════════════════════
# МОДЕЛИ ДАННЫХ
# ═══════════════════════════════════════════════════════════════════════════

class License(Base):
    __tablename__ = "licenses"
    id = Column(Integer, primary_key=True)
    license_key = Column(String(64), unique=True, index=True, nullable=False)
    product_id = Column(String(32), nullable=False, default="monthly")
    status = Column(String(16), default="active")
    customer_email = Column(String(255))
    customer_name = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)
    max_instances = Column(Integer, default=1)
    metadata_json = Column(Text, default="{}")


class Instance(Base):
    __tablename__ = "instances"
    id = Column(Integer, primary_key=True)
    license_key = Column(String(64), index=True, nullable=False)
    instance_id = Column(String(64), unique=True, nullable=False)
    hwid = Column(String(64), nullable=False)
    hostname = Column(String(255))
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)


class CreditBalance(Base):
    __tablename__ = "credit_balances"
    license_key = Column(String(64), primary_key=True)
    balance = Column(Integer, default=0)
    total_granted = Column(Integer, default=0)
    total_consumed = Column(Integer, default=0)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# Создание таблиц
Base.metadata.create_all(bind=engine)


# ═══════════════════════════════════════════════════════════════════════════
# УТИЛИТЫ
# ═══════════════════════════════════════════════════════════════════════════

def verify_signature(payload: dict, sig: str) -> bool:
    if not APP_SHARED_SECRET:
        return True
    data = {k: v for k, v in payload.items() if k != 'sig'}
    canonical = json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')
    expected = hmac.new(APP_SHARED_SECRET.encode('utf-8'), canonical, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)


def sign_response(data: dict, ts: int) -> dict:
    response = {"data": data, "ts": ts}
    if HAS_CRYPTO and SERVER_PRIVATE_KEY_HEX:
        try:
            private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SERVER_PRIVATE_KEY_HEX))
            msg = json.dumps({"data": data, "ts": ts}, sort_keys=True, separators=(',', ':')).encode('utf-8')
            response["sig_ed25519"] = private_key.sign(msg).hex()
        except Exception as e:
            print(f"[!] Sign error: {e}")
    return response


def verify_webhook_signature(payload: bytes, signature: str) -> bool:
    if not LEMON_WEBHOOK_SECRET:
        return True
    expected = hmac.new(LEMON_WEBHOOK_SECRET.encode('utf-8'), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def fetch_license_key_from_lemon(order_id: int) -> str:
    """Получает лицензионный ключ из API Lemon Squeezy по ID заказа"""
    if not LEMON_API_KEY:
        print(f"[!] LEMON_API_KEY not set, cannot fetch license key")
        return None
    
    url = f"https://api.lemonsqueezy.com/v1/orders/{order_id}"
    headers = {
        "Accept": "application/vnd.api+json",
        "Authorization": f"Bearer {LEMON_API_KEY}"
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            # Ищем ключ в атрибутах заказа
            order_attrs = data.get('data', {}).get('attributes', {})
            license_key = order_attrs.get('license_key')
            if license_key:
                print(f"[✓] Fetched license key from Lemon API: {license_key}")
                return license_key
            else:
                print(f"[!] No license_key in order attributes")
                return None
        else:
            print(f"[!] Lemon API error: {response.status_code}")
            return None
    except Exception as e:
        print(f"[!] Error fetching from Lemon API: {e}")
        return None


# ═══════════════════════════════════════════════════════════════════════════
# FASTAPI ПРИЛОЖЕНИЕ
# ═══════════════════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🚀 License Server starting...")
    print(f"🔑 Public key: {SERVER_PUBLIC_KEY_HEX[:32]}...")
    yield
    print("👋 Shutting down...")


app = FastAPI(title="YouTube Localizer License Server", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Health check ────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": time.time()}


@app.get("/pubkey")
async def pubkey():
    return {"public_key": SERVER_PUBLIC_KEY_HEX if SERVER_PUBLIC_KEY_HEX else "not_available"}


# ─── License endpoints ───────────────────────────────────────────────────────
class ActivateRequest(BaseModel):
    license_key: str
    hwid: str
    instance: str
    nonce: str
    ts: int
    sig: str


class ValidateRequest(BaseModel):
    license_key: str
    instance_id: str
    hwid: str
    nonce: str
    ts: int
    sig: str


class DeactivateRequest(BaseModel):
    license_key: str
    instance_id: str
    hwid: str
    nonce: str
    ts: int
    sig: str


@app.post("/license/activate")
async def activate_license(req: ActivateRequest):
    payload = req.model_dump()
    sig = payload.pop("sig", "")
    
    if not verify_signature(payload, sig):
        raise HTTPException(status_code=401, detail="invalid_signature")
    
    now = int(time.time())
    if abs(now - req.ts) > 300:
        raise HTTPException(status_code=400, detail="timestamp_out_of_window")
    
    session = SessionLocal()
    try:
        lic = session.query(License).filter(License.license_key == req.license_key).first()
        if not lic:
            return sign_response({"activated": False, "reason": "invalid_license"}, now)
        
        if lic.status != "active":
            return sign_response({"activated": False, "reason": f"license_{lic.status}"}, now)
        
        if lic.expires_at and lic.expires_at < datetime.utcnow():
            return sign_response({"activated": False, "reason": "expired"}, now)
        
        active_instances = session.query(Instance).filter(
            Instance.license_key == req.license_key,
            Instance.is_active == True
        ).count()
        
        if active_instances >= lic.max_instances:
            return sign_response({"activated": False, "reason": "max_instances_reached"}, now)
        
        instance_id = secrets.token_hex(16)
        new_instance = Instance(
            license_key=req.license_key,
            instance_id=instance_id,
            hwid=req.hwid,
            hostname=req.instance,
            is_active=True
        )
        session.add(new_instance)
        session.commit()
        
        balance = session.query(CreditBalance).filter(CreditBalance.license_key == req.license_key).first()
        if not balance:
            balance = CreditBalance(license_key=req.license_key, balance=10, total_granted=10)
            session.add(balance)
            session.commit()
        
        return sign_response({
            "activated": True,
            "instance_id": instance_id,
            "status": "active",
            "expires_at": lic.expires_at.isoformat() if lic.expires_at else None,
            "meta": {"product_name": "YouTube Localizer", "customer_email": lic.customer_email, "plan": lic.product_id}
        }, now)
        
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()


@app.post("/license/validate")
async def validate_license(req: ValidateRequest):
    payload = req.model_dump()
    sig = payload.pop("sig", "")
    
    if not verify_signature(payload, sig):
        raise HTTPException(status_code=401, detail="invalid_signature")
    
    now = int(time.time())
    if abs(now - req.ts) > 300:
        raise HTTPException(status_code=400, detail="timestamp_out_of_window")
    
    session = SessionLocal()
    try:
        lic = session.query(License).filter(License.license_key == req.license_key).first()
        if not lic:
            return sign_response({"valid": False, "reason": "invalid_license"}, now)
        
        if lic.status != "active":
            return sign_response({"valid": False, "reason": f"license_{lic.status}"}, now)
        
        if lic.expires_at and lic.expires_at < datetime.utcnow():
            return sign_response({"valid": False, "reason": "expired"}, now)
        
        inst = session.query(Instance).filter(
            Instance.license_key == req.license_key,
            Instance.instance_id == req.instance_id
        ).first()
        
        if not inst:
            return sign_response({"valid": False, "reason": "instance_not_found"}, now)
        
        if inst.hwid != req.hwid:
            return sign_response({"valid": False, "reason": "hwid_mismatch"}, now)
        
        inst.last_seen = datetime.utcnow()
        session.commit()
        
        return sign_response({"valid": True, "status": lic.status, "expires_at": lic.expires_at.isoformat() if lic.expires_at else None}, now)
        
    finally:
        session.close()


@app.post("/license/deactivate")
async def deactivate_license(req: DeactivateRequest):
    payload = req.model_dump()
    sig = payload.pop("sig", "")
    
    if not verify_signature(payload, sig):
        raise HTTPException(status_code=401, detail="invalid_signature")
    
    session = SessionLocal()
    try:
        inst = session.query(Instance).filter(Instance.instance_id == req.instance_id).first()
        if inst:
            inst.is_active = False
            session.commit()
        return sign_response({"deactivated": True}, int(time.time()))
    finally:
        session.close()


# ─── Lemon Squeezy Webhook (исправлен — получаем ключ через API) ─────────────
@app.post("/webhook/lemon")
async def lemon_webhook(request: Request, x_signature: Optional[str] = Header(None)):
    """Обработка webhook от Lemon Squeezy — получаем ключ через API"""
    
    body = await request.body()
    
    # Проверка подписи
    if x_signature and not verify_webhook_signature(body, x_signature):
        print(f"[!] Invalid webhook signature")
        raise HTTPException(status_code=401, detail="invalid_signature")
    
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="invalid_json")
    
    event_name = data.get('meta', {}).get('event_name', 'unknown')
    print(f"[✓] Lemon webhook received: {event_name}")
    
    # Обработка события subscription_created
    if event_name == 'subscription_created':
        sub_data = data.get('data', {})
        sub_attrs = sub_data.get('attributes', {})
        
        customer_email = sub_attrs.get('user_email', '')
        customer_name = sub_attrs.get('user_name', '')
        variant_id = sub_attrs.get('variant_id', '')
        order_id = sub_attrs.get('order_id')
        
        print(f"[✓] Order ID: {order_id}, Customer: {customer_email}")
        
        # Пытаемся получить лицензионный ключ через API Lemon Squeezy
        license_key = None
        if order_id and LEMON_API_KEY:
            license_key = fetch_license_key_from_lemon(order_id)
        
        # Если не получили — генерируем свой
        if not license_key:
            license_key = f"LS-{secrets.token_hex(8).upper()}"
            print(f"[!] Could not fetch license key, generated: {license_key}")
        
        expires_at = datetime.utcnow() + timedelta(days=30)
        
        session = SessionLocal()
        try:
            existing = session.query(License).filter(License.license_key == license_key).first()
            if existing:
                print(f"[!] License {license_key} already exists, updating...")
                existing.status = "active"
                existing.customer_email = customer_email
                existing.customer_name = customer_name
                existing.expires_at = expires_at
            else:
                new_license = License(
                    license_key=license_key,
                    product_id=str(variant_id),
                    status="active",
                    customer_email=customer_email,
                    customer_name=customer_name,
                    expires_at=expires_at,
                    max_instances=5
                )
                session.add(new_license)
                print(f"[✓] License created: {license_key} for {customer_email}")
            
            session.commit()
        except Exception as e:
            print(f"[!] Error creating license: {e}")
            session.rollback()
        finally:
            session.close()
    
    return {"status": "ok"}


# ─── Admin endpoints ─────────────────────────────────────────────────────────
@app.post("/admin/create_test_license")
async def create_test_license():
    session = SessionLocal()
    try:
        test_key = "TEST-" + secrets.token_hex(8).upper()
        expires_at = datetime.utcnow() + timedelta(days=30)
        
        license = License(
            license_key=test_key,
            product_id="test_monthly",
            status="active",
            customer_email="test@example.com",
            expires_at=expires_at,
            max_instances=5
        )
        session.add(license)
        session.commit()
        
        return {"license_key": test_key, "expires_at": expires_at.isoformat()}
    finally:
        session.close()


@app.get("/admin/licenses")
async def list_licenses():
    session = SessionLocal()
    try:
        licenses = session.query(License).order_by(License.created_at.desc()).limit(20).all()
        return {
            "licenses": [
                {
                    "license_key": l.license_key,
                    "status": l.status,
                    "customer_email": l.customer_email,
                    "expires_at": l.expires_at.isoformat() if l.expires_at else None,
                    "created_at": l.created_at.isoformat()
                }
                for l in licenses
            ]
        }
    finally:
        session.close()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
