"""
Клиентская часть — заменяет прямые обращения к DB.* в mark.py на HTTP-запросы
к вашему backend-API. Никакой строки подключения к базе тут больше нет и
быть не должно — только публичный (не секретный) адрес самого API.

Добавить в requirements для PyInstaller: requests

В .env теперь достаточно:
    API_BASE_URL=https://<ваш-сервис>.onrender.com
(это НЕ секрет — просто адрес вашего сервера, его утечка ничего не даёт)

device_token хранится не рядом с exe (папка установки может быть доступна
на чтение всем, и её могут пересоздать при апдейте), а в отдельной
пользовательской папке данных — она переживает и обновления, и переустановку
поверх той же машины.
"""

import os
import getpass

import requests

from colorama import Fore, Style

API_BASE_URL = os.environ.get("API_BASE_URL", "http://127.0.0.1:8000")

_TOKEN_DIR = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "Osint Master")
_TOKEN_PATH = os.path.join(_TOKEN_DIR, "device.token")


def _load_token():
    try:
        with open(_TOKEN_PATH, "r", encoding="utf-8") as f:
            token = f.read().strip()
            return token or None
    except OSError:
        return None


def _save_token(token: str):
    os.makedirs(_TOKEN_DIR, exist_ok=True)
    with open(_TOKEN_PATH, "w", encoding="utf-8") as f:
        f.write(token)


def _post(path: str, payload: dict, timeout: int = 40):
    try:
        resp = requests.post(f"{API_BASE_URL}{path}", json=payload, timeout=timeout)
    except requests.RequestException as e:
        print(f"{Fore.RED}Try use VPN or another network connection. Server is not responding.{e}{Style.RESET_ALL}")
        return None
    return resp


def start(hwid: str, console_start):
    """Аналог прежней DB-версии start(): регистрация нового пользователя,
    либо "переезд" уже существующего на device_token, либо обычное
    возобновление сессии — в зависимости от того, что вернул сервер."""
 
    token = _load_token()
 
    if token:
        resp = _post("/auth/resume", {"hwid": hwid, "device_token": token})
        if resp is None:
            return False
        if resp.status_code == 200:
            data = resp.json()
            if data.get("message"):
                print(f"{Fore.BLUE}WARNING: There are new messages for you.{Style.RESET_ALL}")
            console_start()
            return True
        if resp.status_code == 401:
            # токен больше не действителен (например, отозван) — забываем его
            # и пробуем более раннюю ветку заново
            token = None
        else:
            print(f"{Fore.RED}Server error: {resp.status_code} {resp.text}{Style.RESET_ALL}")
            return False
 
    # локального токена нет — либо это старый (до-API) аккаунт на этой
    # машине, либо совсем новая машина
    resp = _post("/auth/claim", {"hwid": hwid})
    if resp is None:
        return False
 
    if resp.status_code == 200:
        _save_token(resp.json()["device_token"])
        console_start()
        return True
 
    if resp.status_code == 404:
        # действительно новая машина — обычная регистрация
        name = input("Enter your name: ")
        pw = getpass.getpass("Enter your password: ")
 
        resp = _post("/auth/register", {"name": name, "password": pw, "hwid": hwid})
        if resp is None:
            return False
 
        if resp.status_code == 200:
            _save_token(resp.json()["device_token"])
            console_start()
            return True
 
        print(f"{Fore.RED}{resp.json().get('detail', resp.text)}{Style.RESET_ALL}")
        return False
 
    # 409 — уже был заклеймлен ранее, а локальный файл с токеном потерян
    # (переустановка ОС, очистка LocalAppData и т.п.). Восстанавливаемся
    # через логин по имени+паролю — сервер выдаст новый device_token взамен
    # старого, при условии что hwid этой машины тот же, что был при регистрации.
    print(f"{Fore.YELLOW}This device was registered before but the local session was lost. "
          f"Log in to recover access.{Style.RESET_ALL}")
    name = input("Enter your name: ")
    pw = getpass.getpass("Enter your password: ")
 
    resp = _post("/auth/login", {"name": name, "password": pw, "hwid": hwid})
    if resp is None:
        return False
 
    if resp.status_code == 200:
        _save_token(resp.json()["device_token"])
        console_start()
        return True
 
    print(f"{Fore.RED}{resp.json().get('detail', resp.text)}{Style.RESET_ALL}")
    return False


def send_message(hwid: str, to_name: str = None, text: str = None):
    token = _load_token()
    if not token:
        print(f"{Fore.RED}Not logged in.{Style.RESET_ALL}")
        return
    to_name = input("Enter receiver name: ") if not to_name else to_name
    text = input(f"you>>{to_name}>> ") if not text else text

    resp = _post("/chat/send", {"hwid": hwid, "device_token": token, "to_name": to_name, "text": text})
    if resp is None:
        return

    if resp.status_code == 200:
        print(f"{Fore.GREEN}Message sent successfully.{Style.RESET_ALL}")
    elif resp.status_code == 404:
        print(f"{Fore.RED}User not found.{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}Error occurred: {resp.json().get('detail', resp.text)}{Style.RESET_ALL}")

def get_status(hwid: str):
    """Чистое чтение своих данных из БД (restart/shutdown/message/d_level/
    tries_th) — без каких-либо изменений на сервере. Можно звать не только
    при старте (это делает start()), но и периодически во время работы,
    чтобы подхватывать restart/shutdown, выставленные уже после запуска.
 
    Возвращает dict с полями, либо None при сетевой ошибке/невалидном токене
    (в последнем случае локальный токен уже стёрт — start() при следующем
    запуске переоформит его через /auth/claim или /auth/register)."""
 
    token = _load_token()
    if not token:
        return None
 
    resp = _post("/auth/resume", {"hwid": hwid, "device_token": token})
    if resp is None:
        return None
 
    if resp.status_code == 200:
        return resp.json()
 
    if resp.status_code == 401:
        # токен отозван/невалиден — не оставляем протухший локальный файл
        try:
            os.remove(_TOKEN_PATH)
        except OSError:
            pass
 
    return None

def update_data(hwid: str, ch="", val=0):
    token = _load_token()
    if not token:
        return None
    
    resp = _post("/post/data", {"hwid": hwid, "ch": ch, "val": val})
    if resp is None:
            return None
     
    if resp.status_code == 200:
        return resp.json()
     
    if resp.status_code == 401:
        # токен отозван/невалиден — не оставляем протухший локальный файл
        try:
            os.remove(_TOKEN_PATH)
        except OSError:
            pass
     
    return None

def read_messages(hwid: str):
    """Забирает и одновременно очищает накопленные сообщения на сервере.
    Возвращает сырую строку вида 'sender->text;sender2->text2;' (или None,
    если сообщений нет / произошла ошибка) — разбор и вывод остаются в
    mark.py, здесь только сетевой вызов."""
    token = _load_token()
    if not token:
        print(f"{Fore.RED}Not logged in.{Style.RESET_ALL}")
        return None
 
    resp = _post("/chat/read", {"hwid": hwid, "device_token": token})
    if resp is None:
        return None
 
    if resp.status_code == 200:
        return resp.json().get("messages")
 
    print(f"{Fore.RED}{resp.json().get('detail', resp.text)}{Style.RESET_ALL}")
    return None
    