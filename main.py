#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
YouTube Localizer License Server v1.0
FastAPI + PostgreSQL + Ed25519 signatures
"""

import os
import json
import time
import hmac
import base64
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String, Integer, DateTime, Text, Boolean, select, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import uvicorn

# ─── Cryptography ──────────────────────────────────────────────────────────────
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# ═══════════════════════════════════════════════════════════════════════════
# Конфигурация
# ═══════════════════════════════════════════════════════════════════════════

# Генерация ключей при первом запуске
SERVER_PRIVATE_KEY_HEX = os.environ.get("SERVER_PRIVATE_KEY", "")
SERVER_PUBLIC_KEY_HEX = ""
APP_SHARED_SECRET = os.environ.get("APP_SHARED_SECRET", "")

# Загрузка или генерация ключей
if SERVER_PRIVATE_KEY_HEX and HAS_CRYPTO:
    try:
        private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SERVER_PRIVATE_KEY_HEX))
        SERVER_PUBLIC_KEY_HEX = private_key.public_key().public_bytes_raw().hex()
        print(f"[✓] Public key loaded from SERVER_PRIVATE_KEY")
        print(f"[✓] Public key: {SERVER_PUBLIC_KEY_HEX[:32]}...")
    except Exception as e:
        print(f"[!] Error loading private key: {e}")
        # Генерируем новый если ключ битый
        private_key = Ed25519PrivateKey.generate()
        SERVER_PRIVATE_KEY_HEX = private_key.private_bytes_raw().hex()
        SERVER_PUBLIC_KEY_HEX = private_key.public_key().public_bytes_raw().hex()
        print(f"[!] Generated new key pair (old SERVER_PRIVATE_KEY was invalid)")
        print(f"[!] SAVE THIS PRIVATE KEY in Render Environment Variables:")
        print(f"SERVER_PRIVATE_KEY={SERVER_PRIVATE_KEY_HEX}")
elif not SERVER_PRIVATE_KEY_HEX and HAS_CRYPTO:
    private_key = Ed25519PrivateKey.generate()
    SERVER_PRIVATE_KEY_HEX = private_key.private_bytes_raw().hex()
    SERVER_PUBLIC_KEY_HEX = private_key.public_key().public_bytes_raw().hex()
    print(f"[!] Generated new key pair (no SERVER_PRIVATE_KEY found)")
    print(f"[!] SAVE THIS PRIVATE KEY in Render Environment Variables:")
    print(f"SERVER_PRIVATE_KEY={SERVER_PRIVATE_KEY_HEX}")
else:
    print(f"[!] No cryptography available - running in DEV mode")
    SERVER_PUBLIC_KEY_HEX = "dev_mode_no_crypto"

if not APP_SHARED_SECRET:
    APP_SHARED_SECRET = secrets.token_hex(32)
    print(f"[!] APP_SHARED_SECRET = \"{APP_SHARED_SECRET}\"")
    print(f"[!] SAVE THIS SHARED SECRET in Render Environment Variables:")
    print(f"APP_SHARED_SECRET={APP_SHARED_SECRET}")

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://localhost/yt_licenses")

print(f"[✓] Cryptography available: {HAS_CRYPTO}")
print(f"[✓] Public key available: {bool(SERVER_PUBLIC_KEY_HEX)}")
print(f"[✓] Shared secret available: {bool(APP_SHARED_SECRET)}")

# ─── Database ─────────────────────────────────────────────────────────────────
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ═══════════════════════════════════════════════════════════════════════════
# Модели данных
# ═══════════════════════════════════════════════════════════════════════════

class License(Base):
    __tablename__ = "licenses"
    
    id = Column(Integer, primary_key=True)
    license_key = Column(String(64), unique=True, index=True, nullable=False)
    product_id = Column(String(32), nullable=False, default="monthly")
    status = Column(String(16), default="active")  # active, expired, revoked
    customer_email = Column(String(255))
    customer_name = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)
    last_validated_at = Column(DateTime)
    
    # Лимиты
    max_instances = Column(Integer, default=1)
    
    # Метаданные
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
    last_ip = Column(String(45))
    is_active = Column(Boolean, default=True)


class CreditBalance(Base):
    __tablename__ = "credit_balances"
    
    license_key = Column(String(64), primary_key=True)
    balance = Column(Integer, default=0)
    total_granted = Column(Integer, default=0)
    total_consumed = Column(Integer, default=0)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class CreditTransaction(Base):
    __tablename__ = "credit_transactions"
    
    id = Column(Integer, primary_key=True)
    license_key = Column(String(64), index=True, nullable=False)
    operation = Column(String(32), nullable=False)  # grant, consume
    amount = Column(Integer, nullable=False)
    units = Column(Integer, default=1)
    description = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow)
    client_nonce = Column(String(64))


# Create tables
Base.metadata.create_all(bind=engine)


# ═══════════════════════════════════════════════════════════════════════════
# Pydantic схемы
# ═══════════════════════════════════════════════════════════════════════════

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


class CreditBalanceRequest(BaseModel):
    license_key: str
    instance_id: str
    hwid: str
    nonce: str
    ts: int
    sig: str


class CreditConsumeRequest(BaseModel):
    license_key: str
    instance_id: str
    hwid: str
    operation: str
    units: int
    client_nonce: str
    nonce: str
    ts: int
    sig: str


# ═══════════════════════════════════════════════════════════════════════════
# Утилиты
# ═══════════════════════════════════════════════════════════════════════════

def verify_signature(payload: dict, sig: str) -> bool:
    """Проверка HMAC-SHA256 подписи запроса"""
    if not APP_SHARED_SECRET:
        return True
    data = {k: v for k, v in payload.items() if k != 'sig'}
    canonical = json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')
    expected = hmac.new(
        APP_SHARED_SECRET.encode('utf-8'),
        canonical,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, sig)


def sign_response(data: dict, ts: int) -> dict:
    """Подпись ответа Ed25519"""
    response = {"data": data, "ts": ts}
    if HAS_CRYPTO and SERVER_PRIVATE_KEY_HEX and SERVER_PUBLIC_KEY_HEX != "dev_mode_no_crypto":
        try:
            private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SERVER_PRIVATE_KEY_HEX))
            msg = json.dumps({"data": data, "ts": ts}, sort_keys=True, separators=(',', ':')).encode('utf-8')
            sig = private_key.sign(msg).hex()
            response["sig_ed25519"] = sig
        except Exception as e:
            print(f"[!] Sign error: {e}")
    return response


def check_license_valid(license_key: str, hwid: str, instance_id: str = None) -> tuple[bool, str, dict]:
    """Проверка валидности лицензии"""
    session = SessionLocal()
    try:
        lic = session.query(License).filter(License.license_key == license_key).first()
        if not lic:
            return False, "invalid_license", {}
        
        if lic.status != "active":
            return False, "license_not_active", {}
        
        if lic.expires_at and lic.expires_at < datetime.utcnow():
            return False, "license_expired", {}
        
        # Проверка instance
        if instance_id:
            inst = session.query(Instance).filter(
                Instance.license_key == license_key,
                Instance.instance_id == instance_id
            ).first()
            if inst:
                if inst.hwid != hwid:
                    return False, "hwid_mismatch", {}
                inst.last_seen = datetime.utcnow()
                session.commit()
        
        return True, "ok", {"license": lic, "session": session}
    except Exception as e:
        session.close()
        return False, str(e), {}


def check_credits(license_key: str, required: int) -> tuple[bool, int, str]:
    """Проверка баланса кредитов"""
    session = SessionLocal()
    try:
        balance = session.query(CreditBalance).filter(CreditBalance.license_key == license_key).first()
        if not balance:
            return False, 0, "no_balance_record"
        
        if balance.balance < required:
            return False, balance.balance, "insufficient_credits"
        
        return True, balance.balance, "ok"
    finally:
        session.close()


# ═══════════════════════════════════════════════════════════════════════════
# FastAPI приложение
# ═══════════════════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🚀 License Server starting...")
    print(f"📊 Database: {DATABASE_URL[:50]}...")
    print(f"🔑 Public key available: {bool(SERVER_PUBLIC_KEY_HEX)}")
    if SERVER_PUBLIC_KEY_HEX and SERVER_PUBLIC_KEY_HEX != "dev_mode_no_crypto":
        print(f"🔑 Public key: {SERVER_PUBLIC_KEY_HEX[:32]}...")
    yield
    print("👋 Shutting down...")


app = FastAPI(title="YouTube Localizer License Server", lifespan=lifespan)

# CORS
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
@app.post("/license/activate")
async def activate_license(req: ActivateRequest):
    """Активация лицензии"""
    # Проверка подписи
    payload = req.model_dump()
    sig = payload.pop("sig", "")
    if not verify_signature(payload, sig):
        raise HTTPException(status_code=401, detail="invalid_signature")
    
    # Проверка timestamp
    now = int(time.time())
    if abs(now - req.ts) > 300:
        raise HTTPException(status_code=400, detail="timestamp_out_of_window")
    
    session = SessionLocal()
    try:
        # Найти лицензию
        lic = session.query(License).filter(License.license_key == req.license_key).first()
        if not lic:
            return sign_response({
                "activated": False,
                "reason": "invalid_license"
            }, now)
        
        if lic.status != "active":
            return sign_response({
                "activated": False,
                "reason": f"license_{lic.status}"
            }, now)
        
        if lic.expires_at and lic.expires_at < datetime.utcnow():
            return sign_response({
                "activated": False,
                "reason": "expired"
            }, now)
        
        # Проверить количество активных инстансов
        active_instances = session.query(Instance).filter(
            Instance.license_key == req.license_key,
            Instance.is_active == True
        ).count()
        
        if active_instances >= lic.max_instances:
            return sign_response({
                "activated": False,
                "reason": "max_instances_reached"
            }, now)
        
        # Создать или обновить инстанс
        instance_id = secrets.token_hex(16)
        new_instance = Instance(
            license_key=req.license_key,
            instance_id=instance_id,
            hwid=req.hwid,
            hostname=req.instance,
            last_ip=req.instance[:50],
            is_active=True
        )
        session.add(new_instance)
        session.commit()
        
        # Создать баланс кредитов если нет
        balance = session.query(CreditBalance).filter(CreditBalance.license_key == req.license_key).first()
        if not balance:
            balance = CreditBalance(
                license_key=req.license_key,
                balance=10,  # Стартовый бонус
                total_granted=10
            )
            session.add(balance)
            session.commit()
        
        return sign_response({
            "activated": True,
            "instance_id": instance_id,
            "status": "active",
            "expires_at": lic.expires_at.isoformat() if lic.expires_at else None,
            "meta": {
                "product_name": "YouTube Localizer",
                "customer_email": lic.customer_email,
                "plan": lic.product_id
            }
        }, now)
        
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()


@app.post("/license/validate")
async def validate_license(req: ValidateRequest):
    """Валидация лицензии"""
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
        
        return sign_response({
            "valid": True,
            "status": lic.status,
            "expires_at": lic.expires_at.isoformat() if lic.expires_at else None
        }, now)
        
    finally:
        session.close()


@app.post("/license/deactivate")
async def deactivate_license(req: DeactivateRequest):
    """Деактивация лицензии"""
    payload = req.model_dump()
    sig = payload.pop("sig", "")
    if not verify_signature(payload, sig):
        raise HTTPException(status_code=401, detail="invalid_signature")
    
    session = SessionLocal()
    try:
        inst = session.query(Instance).filter(
            Instance.instance_id == req.instance_id
        ).first()
        
        if inst:
            inst.is_active = False
            session.commit()
        
        return sign_response({"deactivated": True}, int(time.time()))
        
    finally:
        session.close()


# ─── Credits endpoints ───────────────────────────────────────────────────────
@app.post("/credits/balance")
async def get_balance(req: CreditBalanceRequest):
    """Получить баланс кредитов"""
    payload = req.model_dump()
    sig = payload.pop("sig", "")
    if not verify_signature(payload, sig):
        raise HTTPException(status_code=401, detail="invalid_signature")
    
    session = SessionLocal()
    try:
        balance = session.query(CreditBalance).filter(CreditBalance.license_key == req.license_key).first()
        if not balance:
            return sign_response({"balance": 0, "granted": 0, "consumed": 0}, int(time.time()))
        
        return sign_response({
            "balance": balance.balance,
            "granted": balance.total_granted,
            "consumed": balance.total_consumed
        }, int(time.time()))
        
    finally:
        session.close()


@app.post("/credits/consume")
async def consume_credits(req: CreditConsumeRequest):
    """Списать кредиты"""
    payload = req.model_dump()
    sig = payload.pop("sig", "")
    if not verify_signature(payload, sig):
        raise HTTPException(status_code=401, detail="invalid_signature")
    
    # Стоимость операций
    cost_map = {
        "translate_meta": 1,
        "translate_subs": 5,
        "upload_caption": 1
    }
    
    cost = cost_map.get(req.operation, 1) * req.units
    
    session = SessionLocal()
    try:
        balance = session.query(CreditBalance).filter(CreditBalance.license_key == req.license_key).first()
        if not balance:
            return sign_response({"success": False, "error": "no_balance"}, int(time.time()))
        
        if balance.balance < cost:
            return sign_response({
                "success": False,
                "error": "insufficient_credits",
                "balance": balance.balance
            }, int(time.time()))
        
        balance.balance -= cost
        balance.total_consumed += cost
        balance.updated_at = datetime.utcnow()
        
        transaction = CreditTransaction(
            license_key=req.license_key,
            operation="consume",
            amount=cost,
            units=req.units,
            description=req.operation,
            client_nonce=req.client_nonce
        )
        session.add(transaction)
        session.commit()
        
        return sign_response({
            "success": True,
            "charged": cost,
            "balance": balance.balance
        }, int(time.time()))
        
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()


# ─── Admin endpoints (создание тестовой лицензии) ───────────────────────────
@app.post("/admin/create_test_license")
async def create_test_license():
    """Создать тестовую лицензию (только для разработки)"""
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


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
