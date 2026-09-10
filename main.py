"""
Backend-прокси для Osint Master поверх Neon (Postgres).

Единственное место во всей системе, где лежит DATABASE_URL — переменная
окружения на сервере (Render/Railway/etc), задаётся через дашборд хостинга,
никогда не попадает в .env клиента и не коммитится в git.

Клиент (mark.exe) больше не подключается к базе напрямую — только к этому
API по HTTPS. Идентификация клиента — не голый HWID (его легко подделать по
сети), а device_token: секрет, который сервер выдаёт один раз (при
регистрации нового пользователя, либо при первом "переезде" уже
существующего пользователя на эту схему через /auth/claim) и который клиент
сохраняет у себя локально. Сервер хранит только SHA-256 хеш токена — если
кто-то украдёт дамп базы, токены всё равно нельзя использовать напрямую (как
и с паролями).

Запуск локально для теста:
    pip install -r requirements.txt
    set DATABASE_URL=postgresql://...       (на Windows; на Linux/Mac — export)
    uvicorn main:app --reload
"""

import os
import hashlib
import secrets

import bcrypt
import psycopg2
import psycopg2.pool
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

DATABASE_URL = os.environ["DATABASE_URL"]

app = FastAPI(title="Osint Master API")

connection_pool = psycopg2.pool.ThreadedConnectionPool(1, 10, DATABASE_URL, connect_timeout=5)


def db_connect():
    return connection_pool.getconn()


def release_connection(conn, broken=False):
    try:
        connection_pool.putconn(conn, close=broken)
    except Exception:
        pass


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def db_unavailable():
    return HTTPException(status_code=503, detail="Database unavailable, try again.")


# ---------------------------------------------------------------- schemas --

class RegisterRequest(BaseModel):
    name: str
    password: str
    hwid: str


class ClaimRequest(BaseModel):
    # для пользователей, зарегистрированных ДО перехода на device_token —
    # у них уже есть строка в users с их hwid, но ещё нет device_token_hash.
    # Разрешаем "забрать" токен ровно один раз для такого hwid.
    hwid: str


class ResumeRequest(BaseModel):
    hwid: str
    device_token: str


class ChatRequest(BaseModel):
    hwid: str
    device_token: str
    to_name: str
    text: str


class LoginRequest(BaseModel):
    name: str
    password: str
    hwid: str

class ReadMessagesRequest(BaseModel):
    hwid: str
    device_token: str


# ------------------------------------------------------------- внутреннее --

def _verify_password(stored: str, provided: str) -> bool:
    try:
        return bcrypt.checkpw(provided.encode(), stored.encode())
    except ValueError:
        # legacy-строка: пароль ещё лежит как есть, не в виде bcrypt-хеша
        # (аккаунты, созданные до перехода на API)
        return stored == provided


def _authenticate(conn, hwid: str, device_token: str) -> dict:
    with conn.cursor() as cur:
        cur.execute("SET statement_timeout = 5000")
        cur.execute(
            "SELECT name, device_token_hash, restart, shutdown, message, d_level, tries_th "
            "FROM users WHERE hwid=%s",
            (hwid,),
        )
        row = cur.fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="Not registered.")

    name, token_hash, restart, shutdown, message, d_level, tries_th = row

    if not token_hash or hash_token(device_token) != token_hash:
        raise HTTPException(status_code=401, detail="Invalid device token.")

    return {
        "name": name,
        "restart": restart,
        "shutdown": shutdown,
        "message": message,
        "d_level": d_level,
        "tries_th": tries_th,
    }


# ---------------------------------------------------------------- routes --

@app.post("/auth/register")
def register(req: RegisterRequest):
    conn = db_connect()
    broken = False
    try:
        with conn.cursor() as cur:
            cur.execute("SET statement_timeout = 5000")

            cur.execute("SELECT 1 FROM users WHERE hwid=%s", (req.hwid,))
            if cur.fetchone():
                raise HTTPException(status_code=409, detail="This device is already registered.")

            cur.execute("SELECT 1 FROM users WHERE name=%s", (req.name,))
            if cur.fetchone():
                raise HTTPException(status_code=409, detail="This name is already taken.")

            password_hash = bcrypt.hashpw(req.password.encode(), bcrypt.gensalt()).decode()
            device_token = secrets.token_urlsafe(32)

            cur.execute(
                "INSERT INTO users (name, password, hwid, device_token_hash) VALUES (%s, %s, %s, %s)",
                (req.name, password_hash, req.hwid, hash_token(device_token)),
            )
            cur.execute("INSERT INTO hacks (hwid) VALUES (%s)", (req.hwid,))
        conn.commit()
        return {"device_token": device_token}
    except (psycopg2.OperationalError, psycopg2.InterfaceError):
        broken = True
        raise db_unavailable()
    finally:
        release_connection(conn, broken=broken)


@app.post("/auth/claim")
def claim(req: ClaimRequest):
    """Разовый переезд уже существующего (до-API) пользователя на device_token,
    без необходимости заново вводить пароль — легитимность подтверждается тем,
    что hwid уже был записан в базу раньше, при регистрации напрямую в БД."""
    conn = db_connect()
    broken = False
    try:
        with conn.cursor() as cur:
            cur.execute("SET statement_timeout = 5000")
            cur.execute("SELECT device_token_hash FROM users WHERE hwid=%s", (req.hwid,))
            row = cur.fetchone()

            if row is None:
                raise HTTPException(status_code=404, detail="Not registered.")
            if row[0] is not None:
                raise HTTPException(status_code=409, detail="Already claimed. Use /auth/resume.")

            device_token = secrets.token_urlsafe(32)
            cur.execute(
                "UPDATE users SET device_token_hash=%s WHERE hwid=%s",
                (hash_token(device_token), req.hwid),
            )
        conn.commit()
        return {"device_token": device_token}
    except (psycopg2.OperationalError, psycopg2.InterfaceError):
        broken = True
        raise db_unavailable()
    finally:
        release_connection(conn, broken=broken)


@app.post("/auth/login")
def login(req: LoginRequest):
    """Восстановление доступа по имени+паролю — на случай, если локальный
    device_token потерян (переустановка Windows, очистка LocalAppData,
    и т.п.), но hwid на этой машине тот же самый, что был при регистрации.
    Выдаёт новый device_token взамен старого (старый перестаёт работать)."""
    conn = db_connect()
    broken = False
    try:
        with conn.cursor() as cur:
            cur.execute("SET statement_timeout = 5000")
            cur.execute("SELECT hwid, password FROM users WHERE name=%s", (req.name,))
            row = cur.fetchone()

            if row is None:
                raise HTTPException(status_code=404, detail="User not found.")

            stored_hwid, stored_password = row

            if not _verify_password(stored_password, req.password):
                raise HTTPException(status_code=401, detail="Wrong password.")

            if stored_hwid != req.hwid:
                # смена устройства — сознательно не делаем это автоматическим,
                # это уже вопрос политики (один пароль не должен переносить
                # лицензию на любое железо без ручной проверки)
                raise HTTPException(
                    status_code=403,
                    detail="This account is bound to a different device. Contact support to transfer it.",
                )

            device_token = secrets.token_urlsafe(32)
            new_password_value = (
                stored_password if stored_password.startswith("$2")
                else bcrypt.hashpw(req.password.encode(), bcrypt.gensalt()).decode()
            )
            cur.execute(
                "UPDATE users SET device_token_hash=%s, password=%s WHERE hwid=%s",
                (hash_token(device_token), new_password_value, req.hwid),
            )
        conn.commit()
        return {"device_token": device_token}
    except (psycopg2.OperationalError, psycopg2.InterfaceError):
        broken = True
        raise db_unavailable()
    finally:
        release_connection(conn, broken=broken)


@app.post("/auth/resume")
def resume(req: ResumeRequest):
    conn = db_connect()
    broken = False
    try:
        return _authenticate(conn, req.hwid, req.device_token)
    except (psycopg2.OperationalError, psycopg2.InterfaceError):
        broken = True
        raise db_unavailable()
    finally:
        release_connection(conn, broken=broken)


@app.post("/chat/send")
def chat_send(req: ChatRequest):
    conn = db_connect()
    broken = False
    try:
        me = _authenticate(conn, req.hwid, req.device_token)

        with conn.cursor() as cur:
            cur.execute("SET statement_timeout = 5000")
            cur.execute("SELECT hwid, message FROM users WHERE name=%s", (req.to_name,))
            row = cur.fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="Recipient not found.")

            target_hwid, message_old = row
            # имя отправителя берём из аутентифицированной сессии (me['name']),
            # а не из тела запроса — раньше это можно было подделать
            new_message = f"{message_old if message_old else ''}{me['name']}->{req.text};"
            cur.execute("UPDATE users SET message=%s WHERE hwid=%s", (new_message, target_hwid))
        conn.commit()
        return {"status": "sent"}
    except (psycopg2.OperationalError, psycopg2.InterfaceError):
        broken = True
        raise db_unavailable()
    finally:
        release_connection(conn, broken=broken)


@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/post/data")
def post_data(req: ChatRequest):
    conn = db_connect()
    broken = False
    try:
        with conn.cursor() as cur:
            cur.execute("SET statement_timeout = 5000")
            ch = req.ch
            if ch != "d_level_decr":
                prompt = "UPDATE users SET" + ch + "=%s WHERE hwid=%s"
                cur.execute(prompt, (req.val, req.hwid))
            elif ch == "d_level_decr":
                cur.execute("""
                                UPDATE users
                                SET d_level = GREATEST(d_level - 1, 0)
                            """)
        conn.commit()
        return {"status": "post"}
    except (psycopg2.OperationalError, psycopg2.InterfaceError):
        broken = True
        raise db_unavailable()
    finally:
        release_connection(conn, broken=broken)

@app.post("/chat/read")
def chat_read(req: ReadMessagesRequest):
    """Отдаёт сырую строку накопленных сообщений (формат "sender->text;...")
    и одновременно чистит её в базе — ровно то, что раньше делал клиент
    напрямую через SELECT + UPDATE message=NULL. Разбор по отправителям,
    фильтр по имени и задержка между строками — на стороне клиента,
    серверу об этом знать незачем."""
    conn = db_connect()
    broken = False
    try:
        me = _authenticate(conn, req.hwid, req.device_token)
        messages = me["message"]
 
        if messages:
            with conn.cursor() as cur:
                cur.execute("SET statement_timeout = 5000")
                cur.execute("UPDATE users SET message=NULL WHERE hwid=%s", (req.hwid,))
            conn.commit()
 
        return {"messages": messages}
    except (psycopg2.OperationalError, psycopg2.InterfaceError):
        broken = True
        raise db_unavailable()
    finally:
        release_connection(conn, broken=broken)


