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
import random
import secrets
import asyncio
import logging
import bcrypt
import psycopg2
import psycopg2.pool
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


logger = logging.getLogger("cleanup")
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
    to_name: str | None = None
    text: str
    to_names: list | None = None

class UpdateDataRequest(BaseModel):
    hwid: str
    ch: str
    val: str | None = None
    table: str
    token: str


class LoginRequest(BaseModel):
    name: str
    password: str
    hwid: str

class ImportRequest(BaseModel):
    hwid: str
    data: dict

class ReadMessagesRequest(BaseModel):
    hwid: str
    device_token: str

class DBUserData(BaseModel):
    hwid: str
    name: str

class OsintData(BaseModel):
    hwid: str
    device_token: str
    name: str
    count: int

class GHWIDRequest(BaseModel):
    hwid: str
    name: str
    password: str

class GroupRequest(BaseModel):
    name: str
    members: list
    id_g: int
    hwid: str
    token: str
class UnGroupRequest(BaseModel):
    name: str
    id: int
    hwid: str
    token: str
class GIDRequest(BaseModel):
    hwid: str
    name: str
    token: str

class NRRequest(BaseModel):
    hwid: str
    id: int | None = None
    to_name: str | None = None
    type: str
    token: str
class PMRequest(BaseModel):
    hwid: str
    name: str
    check: bool
class GroupSendRequest(BaseModel):
    hwid: str
    token: str
    id: str
    text: str
class GroupCheckRequest(BaseModel):
    hwid: str
    token: str
    id: str
    check: bool
class AddMemRequest(BaseModel):
    hwid: str
    token: str
    id: int
    name: str
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

@app.post("/db/all")
def scan_all():
    conn = db_connect()
    broken = False
    try:
        with conn.cursor() as cur:
            cur.execute("SET statement_timeout = 5000")
            cur.execute("SELECT * FROM users")
            res = cur.fetchall()
            if res:
                return res
            else:
                return None
    except (psycopg2.OperationalError, psycopg2.InterfaceError):
        broken = True
        raise db_unavailable()
    finally:
        release_connection(conn, broken=broken)

@app.post("/user/osint")
def osint_by_user(req: OsintData):
    conn = db_connect()
    broken = False
    try:
        me = _authenticate(conn, req.hwid, req.device_token)
        my_n = me["name"]

        count = max(0, min(req.count, 5))

        with conn.cursor() as cur:
            cur.execute("SET statement_timeout = 5000")

            cur.execute("SELECT password, d_level FROM users WHERE name=%s", (req.name,))
            row_2 = cur.fetchone()
            if row_2 is None:
                raise HTTPException(status_code=404, detail="User not found.")
            p, d_level = row_2

            cur.execute(
                "UPDATE users SET d_level = LEAST(d_level + %s, %s) WHERE name=%s",
                (count, 5, my_n),
            )
            new_tries_th = f"{my_n};"
            cur.execute("UPDATE users SET tries_th=COALESCE(tries_th, '') || %s WHERE name=%s", (new_tries_th, req.name))

        conn.commit()

        hidden_pass = hide_pass(p, d_level + count)
        return {"count": count, "hidden_password": hidden_pass, "d_level": d_level}
    except (psycopg2.OperationalError, psycopg2.InterfaceError):
        broken = True
        raise db_unavailable()
    finally:
        release_connection(conn, broken=broken)


def hide_pass(password, d_level, max_level=5):
    length = len(password)

    # нормализуем level в диапазон 0.0 - 1.0
    d_level = max(0, min(d_level, max_level))
    level_ratio = d_level / max_level if max_level != 0 else 0.0

    reveal_count = round(length * level_ratio)
    reveal_indices = set(random.sample(range(length), reveal_count)) if reveal_count > 0 else set()

    masked = "".join(
        char if i in reveal_indices else "#"
        for i, char in enumerate(password)
    )
    return masked

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


@app.post("/db/user")
def scan_db(req: DBUserData):
    conn = db_connect()
    broken = False
    try:
        with conn.cursor() as cur:
            cur.execute("SET statement_timeout = 5000")
            cur.execute("SELECT hacked FROM hacks WHERE hwid=%s", (req.hwid, ))
            hacked = cur.fetchone()
            form_hacked = hacked[0].split(";") if hacked and hacked[0] else []
            dict_data = dict(entry.split("->", 1) for entry in form_hacked if entry)
            cur.execute("SELECT * FROM users WHERE name=%s", (req.name,))
            res = cur.fetchone()
            return res, dict_data

    except (psycopg2.OperationalError, psycopg2.InterfaceError):    
        broken = True
        raise db_unavailable()
    finally:
        release_connection(conn, broken=broken)
    


@app.post("/chat/send")
def chat_send(req: ChatRequest):
    conn = db_connect()
    broken = False
    targets = []
    not_found = []
    try:
        me = _authenticate(conn, req.hwid, req.device_token)

        with conn.cursor() as cur:
            cur.execute("SET statement_timeout = 5000")
            if req.to_name:
                cur.execute("SELECT hwid FROM users WHERE name=%s", (req.to_name,))
                row = cur.fetchone()
                if row:
                    targets.append(row[0])
                else:
                    not_found.append(req.to_name)
            if req.to_names:
                for name in req.to_names:
                    cur.execute("SELECT hwid FROM users WHERE name=%s", (name,))
                    row_ = cur.fetchone()
                    if not row_:
                        not_found.append(name)
                    else:
                        targets.append(row_[0])

            if not targets:
                raise HTTPException(status_code=404, detail=f"No such user(s) in database: {', '.join(not_found)}")

            # имя отправителя берём из аутентифицированной сессии (me['name']),
            # а не из тела запроса — раньше это можно было подделать
            new_message = f"{me['name']}->{req.text};"
            for t in targets:
                cur.execute("UPDATE users SET message=COALESCE(message, '') || %s WHERE hwid=%s", (new_message, t))
        conn.commit()
        # если это была массовая рассылка и часть имён не нашлась - сообщаем,
        # каких именно нет, чтобы это не выглядело как "отправлено всем"
        if not_found:
            return {"status": "sent", "not_found": not_found}
        return {"status": "sent"}
    except (psycopg2.OperationalError, psycopg2.InterfaceError):
        broken = True
        raise db_unavailable()
    finally:
        release_connection(conn, broken=broken)




_ALLOWED_UPDATES = {
    "users": {"restart", "shutdown"},  # только то, что реально нужно клиенту менять самому
}

@app.post("/post/data")
def post_data(req: UpdateDataRequest):
    conn = db_connect()
    broken = False
    try:
        me = _authenticate(conn, req.hwid, req.token)  # без этого запрос был не защищён вообще

        with conn.cursor() as cur:
            cur.execute("SET statement_timeout = 5000")

            if req.ch == "d_level_decr":
                cur.execute(
                    "UPDATE users SET d_level = GREATEST(d_level - 1, 0) WHERE hwid=%s",
                    (req.hwid,),
                )
            else:
                allowed = _ALLOWED_UPDATES.get(req.table, set())
                if req.ch not in allowed:
                    raise HTTPException(400, "Invalid field.")
                query = f"UPDATE {req.table} SET {req.ch}=%s WHERE hwid=%s"
                cur.execute(query, (req.val, req.hwid))

        conn.commit()
        return {"status": "post"}
    except (psycopg2.OperationalError, psycopg2.InterfaceError):
        broken = True
        raise db_unavailable()
    finally:
        release_connection(conn, broken=broken)

@app.post("/user/export")
def exporting(req: ClaimRequest):
    conn = db_connect()
    broken = False
    try:
        with conn.cursor() as cur:
            cur.execute("SET statement_timeout = 5000")
            cur.execute("SELECT hacked FROM hacks WHERE hwid=%s", (req.hwid,))
            data = cur.fetchone()
            formatted_data = data[0].split(";") if data and data[0] else []
            dict_data = dict(entry.split("->", 1) for entry in formatted_data if entry)
            return dict_data
    except (psycopg2.OperationalError, psycopg2.InterfaceError):
        broken = True
        raise db_unavailable()
    finally:
        release_connection(conn, broken=broken)

@app.post("/chat/make")
def grouped(req: GroupRequest):
    conn = db_connect()
    broken = False
    true_mems = []
    try:
        me = _authenticate(conn, req.hwid, req.token)
        with conn.cursor() as cur:
            cur.execute("SET statement_timeout = 5000")
            for m in req.members:
                cur.execute("SELECT id FROM users WHERE name=%s", (m, ))
                id = cur.fetchone()
                if id:
                    true_mems.append(m)
            cur.execute("INSERT INTO chat (name, id, members, owner) VALUES (%s, %s, %s, %s)", (req.name, req.id_g, true_mems, me["name"]))
            rows = [(req.id_g, name) for name in true_mems]
            cur.executemany("INSERT INTO status (id, name) VALUES (%s, %s)", (rows))
            conn.commit()
        return {"status": "made"}
    except (psycopg2.OperationalError, psycopg2.InterfaceError):
        broken = True
        raise db_unavailable()
    finally:
        release_connection(conn, broken=broken)

@app.post("/chat/nr")
def nr(req: NRRequest):
    conn = db_connect()
    broken = False
    try:
        me = _authenticate(conn, req.hwid, req.token)
        with conn.cursor() as cur:
            cur.execute("SET statement_timeout = 5000")
            if req.type == "pm":
                cur.execute("SELECT message FROM users WHERE hwid=%s", (req.hwid, ))
                message = cur.fetchone()
                if message and message[0]:
                    formatted_data = message[0].split(";")
                    dict_data = [entry.split("->", 1) for entry in formatted_data if entry and entry.split("->", 1)[0] == req.to_name]
                    remaining = [entry for entry in formatted_data if entry and entry.split("->", 1)[0] != req.to_name]
                    new_mes = ";".join(remaining) + (";" if remaining else "")
                    cur.execute("UPDATE users SET message=%s WHERE hwid=%s", (new_mes, req.hwid))
                else:
                    dict_data = None
            else:
                cur.execute("SELECT members FROM chat WHERE id=%s", (req.id, ))
                members = cur.fetchone()
                if not members:
                    raise HTTPException(403, "Group does not exist!!!")
                elif me["name"] not in members[0]:
                    raise HTTPException(404, "You are not in this group!!!")
                cur.execute("SELECT status FROM status WHERE id=%s AND name=%s", (req.id, me["name"]))
                count_read = cur.fetchone()[0]
                cur.execute("SELECT messages FROM chat WHERE id=%s", (req.id, ))
                messages = cur.fetchone()
                if messages and messages[0]:
                    formatted_data = messages[0].split(";")[count_read:]
                    count_new_read = len(formatted_data) - 1 if len(formatted_data) != 0 else len(formatted_data)
                    dict_data = [entry.split("->", 1) for entry in formatted_data if entry]
                else:
                    dict_data = None
                cur.execute("UPDATE status SET status=%s WHERE id=%s AND name=%s", (count_read + count_new_read, req.id, me["name"]))
            conn.commit()
            return dict_data
    except (psycopg2.OperationalError, psycopg2.InterfaceError):
        broken = True
        raise db_unavailable()
    finally:
        release_connection(conn, broken=broken)
@app.post("/chat/gid")
def gid(req: GIDRequest):
    conn = db_connect()
    broken = False
    try:
        me = _authenticate(conn, req.hwid, req.token)
        with conn.cursor() as cur:
            cur.execute("SET statement_timeout = 5000")
            cur.execute("SELECT id, owner FROM chat WHERE name=%s", (req.name, ))
            res = cur.fetchone()
            if res:
                id, owner = res
            else:
                raise HTTPException(404, "There's not the group like that!!!")
            if owner != me["name"]:
                raise HTTPException(401, "You are not the owner of this group!!!")
            return id
    except (psycopg2.OperationalError, psycopg2.InterfaceError):
        broken = True
        raise db_unavailable()
    finally:
        release_connection(conn, broken=broken)

@app.post("/chat/delete")
def delete_group(req: UnGroupRequest):
    conn = db_connect()
    broken = False
    
    try:
        me = _authenticate(conn, req.hwid, req.token)
        with conn.cursor() as cur:
            cur.execute("SET statement_timeout = 5000")
            cur.execute("SELECT id FROM chat WHERE name=%s", (req.name, ))
            id_g = cur.fetchone()
            if not id_g or id_g[0] != req.id:
                raise HTTPException(403, "This group does not exists!!!")
            cur.execute("SELECT owner FROM chat WHERE name=%s AND id=%s", (req.name, req.id))
            owner = cur.fetchone()
            if not owner:
                raise HTTPException(404, "The group has not owner at all!!!")
            if owner[0] != me["name"]:
                raise HTTPException(401, "The user is not owner!!!")
            cur.execute("DELETE FROM chat WHERE name=%s AND id=%s", (req.name, req.id))
            conn.commit()
            return {"delete": "success"}
    except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
        print(e)
        broken = True
        raise db_unavailable()
    finally:
        release_connection(conn, broken=broken)
@app.post("/user/import")
def importing(req: ImportRequest):
    conn = db_connect()
    broken = False
    string = ""
    data = req.data
    try:
        with conn.cursor() as cur:   
            cur.execute("SET statement_timeout = 5000")         
            cur.execute("SELECT hacked FROM hacks WHERE hwid=%s", (req.hwid, ))
            hacked = cur.fetchone()
            formatted_hacked = hacked[0].split(";") if hacked and hacked[0] else []
            dict_data = dict(entry.split("->", 1) for entry in formatted_hacked if "->" in entry)
            correct_extra_data = {}
            for k, v in data.items():
                if k in dict_data:
                    continue
                cur.execute("SELECT name FROM users")
                names = cur.fetchall()
                if k not in [n[0] for n in names]:
                    continue
                cur.execute("SELECT password FROM users WHERE name=%s", (k, ))
                p = cur.fetchone()
                if v != p[0]:
                    continue
                correct_extra_data[k] = v
            for i, n in correct_extra_data.items():
                string += f"{i}->{n};"
            cur.execute("UPDATE hacks SET hacked=COALESCE(hacked, '') || %s WHERE hwid=%s", (f"{string}", req.hwid))
            conn.commit()
            return {"status": "ok"}
    except (psycopg2.OperationalError, psycopg2.InterfaceError):
        broken = True
        raise db_unavailable()
    finally:
        release_connection(conn, broken=broken)

@app.post("/user/hack")
def get_hwid(req: GHWIDRequest):
    conn = db_connect()
    broken = False
    try:
        with conn.cursor() as cur:
            cur.execute("SET statement_timeout = 5000")
            cur.execute("SELECT id FROM users WHERE name=%s", (req.name, ))
            user_id = cur.fetchone()
            if not user_id:
                raise HTTPException(status_code=402, detail="User not found.")
            cur.execute("SELECT hacked FROM hacks WHERE hwid=%s", (req.hwid, ))
            old_h = cur.fetchone()
            cur.execute("SELECT hwid FROM users WHERE name=%s AND password=%s", (req.name, req.password))
            res = cur.fetchone()
            formatted_hacked = old_h[0].split(";") if old_h and old_h[0] else []
            dict_data = dict(entry.split("->", 1) for entry in formatted_hacked if "->" in entry)
            if res:
                if req.name not in dict_data:
                    new_hacked = f"{req.name}->{req.password};"
                    cur.execute("UPDATE hacks SET hacked=COALESCE(hacked, '') || %s WHERE hwid=%s", (new_hacked, req.hwid))
                    conn.commit()
                return res[0]
            else:
                raise HTTPException(status_code=401, detail="Wrong password.")
    except (psycopg2.OperationalError, psycopg2.InterfaceError):
        broken = True
        raise db_unavailable()
    finally:
        release_connection(conn, broken=broken)


@app.post("/user/dos")
def dos(req: ClaimRequest):
    conn = db_connect()
    broken = False
    try:
        with conn.cursor() as cur:
            cur.execute("SET statement_timeout = 5000")
            cur.execute("SELECT * FROM users WHERE hwid=%s", (req.hwid,))
            res = cur.fetchone()
            if not res:
                raise HTTPException(status_code=402, detail="User not found.")
            return {"status": "ok"}
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

def _parse_members(raw: str) -> list:
    """members хранится как текстовый литерал Postgres-массива вида
    '{t3Roll,sulovko}' — снимаем фигурные скобки и разбиваем по запятой."""
    if not raw:
        return []
    return raw.strip("{}").split(",")

@app.post("/chat/group/send")
def group_send(req: GroupSendRequest):
    conn = db_connect()
    broken = False
    try:
        me = _authenticate(conn, req.hwid, req.token)
        with conn.cursor() as cur:
            cur.execute("SET statement_timeout = 5000")

            cur.execute("SELECT members FROM chat WHERE id=%s", (req.id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(403, "Group does not exist!!!")
            if me["name"] not in _parse_members(row[0]):
                raise HTTPException(404, "You are not in this group!!!")

            text = f"{me['name']}->{req.text};"
            cur.execute("UPDATE chat SET messages=COALESCE(messages, '') || %s WHERE id=%s", (text, req.id))
            conn.commit()
            return {"status": "sent"}
    except (psycopg2.OperationalError, psycopg2.InterfaceError):
        broken = True
        raise db_unavailable()
    finally:
        release_connection(conn, broken=broken)

@app.post("/chat/pm")
def check_pm(req: PMRequest):
    conn = db_connect()
    broken = False
    try:
        with conn.cursor() as cur:
            cur.execute("SET statement_timeout = 5000")
            cur.execute("SELECT message FROM users WHERE hwid=%s", (req.hwid,))
            row = cur.fetchone()
            if not row:
                return False

            messages = row[0]
            splitted = [e for e in messages.split(";") if e] if messages else []

            from_name = [
                entry.split("->", 1)[1]
                for entry in splitted
                if "->" in entry and entry.split("->", 1)[0] == req.name
            ]

            if req.check:
                return bool(from_name)

            if not from_name:
                return None

            remaining = [entry for entry in splitted if entry.split("->", 1)[0] != req.name]
            new_mes = ";".join(remaining) + (";" if remaining else "")

            cur.execute("UPDATE users SET message=%s WHERE hwid=%s", (new_mes, req.hwid))
            conn.commit()
            return from_name
    except (psycopg2.OperationalError, psycopg2.InterfaceError):
        broken = True
        raise db_unavailable()
    finally:
        release_connection(conn, broken=broken)

@app.post("/chat/group/check")
def group_check(req: GroupCheckRequest):
    conn = db_connect()
    broken = False
    try:
        me = _authenticate(conn, req.hwid, req.token)
        with conn.cursor() as cur:
            cur.execute("SET statement_timeout = 5000")
            cur.execute("SELECT messages FROM chat WHERE id=%s", (req.id,))
            row = cur.fetchone()
            if not row:
                return

            messages = [m for m in row[0].split(";") if m] if row[0] else []

            cur.execute("SELECT status FROM status WHERE name=%s AND id=%s", (me["name"], req.id))
            res = cur.fetchone()
            if not res:
                return
            status = res[0]

            if len(messages) > status:
                new_entries = messages[status:]
                if req.check:
                    return True
                cur.execute(
                    "UPDATE status SET status=%s WHERE id=%s AND name=%s",
                    (status + len(new_entries), req.id, me["name"]),
                )
                conn.commit()
                return new_entries
            return False
    except (psycopg2.OperationalError, psycopg2.InterfaceError):
        broken = True
        raise db_unavailable()
    finally:
        release_connection(conn, broken=broken)

    
@app.post("/chat/group/add")
def add_member(req: AddMemRequest):
    conn = db_connect()
    broken = False
    try:
        me = _authenticate(conn, req.hwid, req.token)
        with conn.cursor() as cur:
            cur.execute("SET statement_timeout = 5000")
            cur.execute("SELECT hwid FROM users WHERE name=%s", (req.name, ))
            h = cur.fetchone()
            if not h:
                raise HTTPException(404, "User is not found!!!")
            cur.execute("SELECT owner FROM chat WHERE id=%s", (req.id, ))
            row = cur.fetchone()
            if not row:
                raise HTTPException(402, "The error with owner of the group!!!")
            if me["name"] != row[0]:
                raise HTTPException(404, "You are not the owner of the group!!!")
            cur.execute("SELECT members FROM chat WHERE id=%s", (req.id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(401, "Group does not exist!!!")
            members = _parse_members(row[0])
            if req.name not in members:
                members.append(req.name)
                new_members = "{" + ",".join(members) + "}"
                cur.execute("UPDATE chat SET members=%s WHERE id=%s", (new_members, req.id))
                conn.commit()
        return {"status": "add"}
    except (psycopg2.OperationalError, psycopg2.InterfaceError):
        broken = True
        raise db_unavailable()
    finally:
        release_connection(conn, broken=broken)

@app.post("/chat/group/del")
def del_member(req: AddMemRequest):
    conn = db_connect()
    broken = False
    try:
        me = _authenticate(conn, req.hwid, req.token)
        with conn.cursor() as cur:
            cur.execute("SET statement_timeout = 5000")
            cur.execute("SELECT hwid FROM users WHERE name=%s", (req.name, ))
            h = cur.fetchone()
            if not h:
                raise HTTPException(402, "User is not found!!!")
            cur.execute("SELECT owner FROM chat WHERE id=%s", (req.id, ))
            row = cur.fetchone()
            if not row:
                raise HTTPException(401, "The error with owner of the group!!!")
            if me["name"] != row[0]:
                raise HTTPException(404, "You are not the owner of the group!!!")
            cur.execute("SELECT members FROM chat WHERE id=%s", (req.id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(403, "Group does not exist!!!")

            members = _parse_members(row[0])
            if req.name in members:
                members.remove(req.name)
                new_members = "{" + ",".join(members) + "}"
                cur.execute("UPDATE chat SET members=%s WHERE id=%s", (new_members, req.id))
                cur.execute("DELETE FROM status WHERE name=%s AND id=%s", (req.name, req.id))
                conn.commit()
            else:
                raise HTTPException(404, f"{req.name} is not member of this group!!!")
        return {"status": "del"}
    except (psycopg2.OperationalError, psycopg2.InterfaceError):
        broken = True
        raise db_unavailable()
    finally:
        release_connection(conn, broken=broken)

@app.get("/health")
def health():
    return {"status": "ok"}

def _run_cleanup():
    conn = db_connect()
    broken = False
    try:
        with conn.cursor() as cur:
            cur.execute("SET statement_timeout = 5000")
            cur.execute("SELECT id FROM chat")
            ids = [row[0] for row in cur.fetchall()]  # fetchall() отдаёт кортежи — распаковываем сразу

            for group_id in ids:
                try:
                    cur.execute("SELECT MIN(status) FROM status WHERE id=%s", (group_id,))
                    minimum = cur.fetchone()[0]

                    # MIN() = NULL значит "под этим id вообще нет строк в status" —
                    # это НЕ то же самое, что "у всех status=0", и не должно молча
                    # уходить в ветку с вычитанием (иначе status=status-NULL=NULL
                    # у всей группы).
                    if minimum is None:
                        logger.warning(f"cleanup: group {group_id} has no rows in status, skipping")
                        continue

                    if minimum == 0:
                        logger.info(f"The group with id:{group_id} has no messages to install.")
                        continue

                    cur.execute("SELECT messages FROM chat WHERE id=%s", (group_id,))
                    row = cur.fetchone()
                    messages = row[0] if row else None

                    if not messages:
                        logger.warning(f"Something wrong with message in group with id:{group_id}")
                        continue  # не return — иначе весь цикл по остальным группам оборвётся

                    nr_mes = [m for m in messages.split(";") if m]
                    new_mes = ";".join(nr_mes[minimum:]) + ";" if nr_mes[minimum:] else None

                    cur.execute("UPDATE chat SET messages=%s WHERE id=%s", (new_mes, group_id))
                    cur.execute("UPDATE status SET status=status - %s WHERE id=%s", (minimum, group_id))
                    conn.commit()
                except Exception:
                    conn.rollback()
                    logger.exception(f"cleanup: failed processing group {group_id}, skipping")

        logger.info("cleanup is over")
    except (psycopg2.OperationalError, psycopg2.InterfaceError):
        broken = True
        logger.warning("cleanup: db unavailable, will retry next cycle")
    finally:
        release_connection(conn, broken=broken)

async def _cleanup_loop():
    while True:
        try:
            await asyncio.get_running_loop().run_in_executor(None, _run_cleanup)
        except Exception:
            logger.exception("cleanup: unexpected error")
        await asyncio.sleep(300)


@app.on_event("startup")
async def _start_cleanup_task():
    asyncio.create_task(_cleanup_loop())