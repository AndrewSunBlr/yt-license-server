#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
YouTube Localizer License Server v3.0
- Проверка лицензий через Lemon Squeezy API
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
LEMON_API_KEY = os.environ.get("LEMON_API_KEY", "")

SERVER_PUBLIC_KEY_HEX = ""
if SERVER_PRIVATE_KEY_HEX and HAS_CRYPTO:
    try:
        private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SERVER_PRIVATE_KEY_HEX))
        SERVER_PUBLIC_KEY_HEX = private_key.public_key().public_bytes_raw().hex()
    except Exception:
        private_key = Ed25519PrivateKey.generate()
        SERVER_PRIVATE_KEY_HEX = private_key.private_bytes_raw().hex()
        SERVER_PUBLIC_KEY_HEX = private_key.public_key().public_bytes_raw().hex()
else:
    private_key = Ed25519PrivateKey.generate()
    SERVER_PRIVATE_KEY_HEX = private_key.private_bytes_raw().hex()
    SERVER_PUBLIC_KEY_HEX = private_key.public_key().public_bytes_raw().hex()

print(f"[✓] Public key: {SERVER_PUBLIC_KEY_HEX[:32]}...")

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
        except Exception:
            pass
    return response


def verify_license_with_lemon(license_key: str) -> dict:
    """Проверяет лицензионный ключ через API Lemon Squeezy"""
    if not LEMON_API_KEY:
        return {"valid": False, "reason": "no_api_key"}
    
    url = "https://api.lemonsqueezy.com/v1/licenses/validate"
    headers = {
        "Accept": "application/vnd.api+json",
        "Authorization": f"Bearer {LEMON_API_KEY}"
    }
    data = {"license_key": license_key}
    
    try:
        response = requests.post(url, json=data, headers=headers, timeout=10)
        if response.status_code == 200:
            result = response.json()
            valid = result.get('valid', False)
            if valid:
                return {
                    "valid": True,
                    "customer_email": result.get('customer_email'),
                    "customer_name": result.get('customer_name'),
                    "product_name": result.get('product_name'),
                    "expires_at": result.get('expires_at')
                }
            else:
                return {"valid": False, "reason": "invalid_key"}
        else:
            return {"valid": False, "reason": f"api_error_{response.status_code}"}
    except Exception as e:
        return {"valid": False, "reason": str(e)}


# ═══════════════════════════════════════════════════════════════════════════
# FASTAPI ПРИЛОЖЕНИЕ
# ═══════════════════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🚀 License Server starting...")
    yield


app = FastAPI(title="YouTube Localizer License Server", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/pubkey")
async def pubkey():
    return {"public_key": SERVER_PUBLIC_KEY_HEX if SERVER_PUBLIC_KEY_HEX else "not_available"}


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
    
    # Сначала проверяем в локальной БД
    session = SessionLocal()
    try:
        lic = session.query(License).filter(License.license_key == req.license_key).first()
        
        # Если нет в БД — проверяем через Lemon API
        if not lic and LEMON_API_KEY:
            lemon_result = verify_license_with_lemon(req.license_key)
            if lemon_result.get("valid"):
                # Сохраняем валидную лицензию из Lemon в БД
                lic = License(
                    license_key=req.license_key,
                    product_id="lemon_monthly",
                    status="active",
                    customer_email=lemon_result.get("customer_email", ""),
                    customer_name=lemon_result.get("customer_name", ""),
                    expires_at=datetime.utcnow() + timedelta(days=30),
                    max_instances=5
                )
                session.add(lic)
                session.commit()
                print(f"[✓] License from Lemon saved: {req.license_key}")
            else:
                return sign_response({"activated": False, "reason": "invalid_license"}, now)
        
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
