import asyncio
from contextlib import asynccontextmanager
from datetime import datetime
import json
import logging
import os
import socket
import time
import uuid
from typing import Dict, Any, Optional, Set, List

import requests
from requests.adapters import HTTPAdapter
import urllib3.util.connection as urllib3_cn
from urllib3.util import Retry
import uvicorn
from fastapi import (
    FastAPI,
    Request,
    WebSocket,
    WebSocketDisconnect,
    Form,
    HTTPException,
    Depends,
    status
)
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select, delete

from database import (
    init_db,
    async_session,
    User,
    Token,
    Device,
    get_or_create_user,
    add_user_token,
    get_user_by_token,
    get_user_devices,
    get_user_devices_query,
    save_or_update_device,
    delete_device,
    delete_token,
    clear_user_devices,
    delete_user_account,
    update_device_states,
    get_all_users_details,
    get_token_by_refresh,
    rotate_token
)

import config

log_level = getattr(logging, config.LOG_LEVEL, logging.INFO)
logging.basicConfig(
    level=log_level,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("smart_home_gateway")

# Принудительно используем IPv4 для предотвращения таймаутов на немаршрутизируемых IPv6 адресах Яндекса
try:
    urllib3_cn.allowed_gai_family = lambda: socket.AF_INET
except Exception:
    pass

# Пул постоянных HTTP-соединений с Keep-Alive для снижения задержек
yandex_session = requests.Session()
retries = Retry(
    total=2,
    backoff_factor=0.2,
    status_forcelist=[500, 502, 503, 504],
    raise_on_status=False
)
adapter = HTTPAdapter(pool_connections=20, pool_maxsize=50, max_retries=retries)
yandex_session.mount("https://", adapter)
yandex_session.mount("http://", adapter)


# =====================================================================
# 1. КОНФИГУРАЦИЯ И ПАРАМЕТРЫ
# =====================================================================
YANDEX_OAUTH_CLIENT_ID = config.YANDEX_OAUTH_CLIENT_ID
YANDEX_OAUTH_SECRET = config.YANDEX_OAUTH_SECRET

SMART_HOME_CLIENT_ID = config.SMART_HOME_CLIENT_ID
SMART_HOME_CLIENT_SECRET = config.SMART_HOME_CLIENT_SECRET

SKILLS_ID = config.YANDEX_SKILLS_ID
SKILL_OAUTH_TOKEN = config.YANDEX_SKILL_OAUTH_TOKEN

# Временное хранилище OAuth сессий
auth_sessions: Dict[str, dict] = {}   # state -> {redirect_uri, state}
auth_codes: Dict[str, dict] = {}       # code -> {yandex_uid, email, display_name}

SERVER_START_TIME = time.time()


def format_uptime(seconds: float) -> str:
    secs = int(seconds)
    days, secs = divmod(secs, 86400)
    hours, secs = divmod(secs, 3600)
    minutes, secs = divmod(secs, 60)
    parts = []
    if days > 0:
        parts.append(f"{days} д.")
    if hours > 0 or days > 0:
        parts.append(f"{hours} ч.")
    parts.append(f"{minutes} мин.")
    parts.append(f"{secs} сек.")
    return " ".join(parts)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Инициализация БД и миграция при старте
    await init_db()
    logger.info("База данных SQLite успешно инициализирована")
    yield


app = FastAPI(title="Yandex Smart Home Gateway", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =====================================================================
# 2. АУТЕНТИФИКАЦИЯ И ОПРЕДЕЛЕНИЕ ПОЛЬЗОВАТЕЛЯ
# =====================================================================

async def get_current_user_obj(request: Request) -> User:
    """
    Определяет пользователя по Bearer-токену из Authorization, тела JSON или query.
    Включает подробное дебаг-логирование причин отказа в доступе.
    """
    token = None
    source = "none"

    # 1. Из заголовка Authorization (Bearer <token>)
    auth_header = request.headers.get("Authorization") or request.headers.get("authorization")
    if auth_header:
        parts = auth_header.split(" ", 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1].strip()
            source = "Authorization header"
        elif len(parts) == 1 and parts[0].strip().startswith("gtw_"):
            token = parts[0].strip()
            source = "Authorization header (direct)"

    # 2. Если нет в заголовке — проверяем JSON-тело
    if not token and request.method in ("POST", "PUT", "DELETE", "PATCH"):
        try:
            body = await request.json()
            if isinstance(body, dict):
                cand = body.get("token") or body.get("access_token")
                if cand and isinstance(cand, str):
                    token = cand.strip()
                    source = "JSON body"
        except Exception:
            pass

    # 3. Если нет в теле — проверяем query-параметры (?token=...)
    if not token:
        cand = request.query_params.get("token") or request.query_params.get("access_token")
        if cand:
            token = cand.strip()
            source = "query param"

    # Очистка токена: если он обёрнут в JSON-строку {"access_token":"..."}
    if token and token.startswith("{"):
        try:
            parsed = json.loads(token)
            if isinstance(parsed, dict) and "access_token" in parsed:
                token = str(parsed["access_token"]).strip()
        except Exception:
            pass

    # Снятие лишних кавычек
    if token and (token.startswith('"') or token.startswith("'")):
        token = token.strip('"\'')

    client_ip = request.client.host if request.client else "unknown"
    token_preview = (token[:18] + "...") if token and len(token) > 18 else (token or "None")

    if not token:
        logger.warning(
            f"❌ [AUTH 401] {request.method} {request.url.path} (от {client_ip}): "
            f"токен не передан ни в заголовке Authorization, ни в теле запроса, ни в query"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Требуется авторизация: токен не найден в заголовке Authorization, теле запроса или параметрах",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if token in ("local-token", "__PWRD__"):
        logger.warning(
            f"❌ [AUTH 401] {request.method} {request.url.path} (от {client_ip}): "
            f"передан фиктивный токен '{token}'. В ноде требуется привязка реального аккаунта через кнопку 'Получить токен'."
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Недействительный токен: требуется привязка аккаунта через Яндекс ID",
            headers={"WWW-Authenticate": "Bearer"},
        )

    async with async_session() as session:
        user = await get_user_by_token(session, token)
        if user:
            logger.info(
                f"✅ [AUTH OK] {request.method} {request.url.path} | пользователь: {user.email} (UID: {user.yandex_uid}, ID: {user.id}) | токен: {token_preview} [{source}]"
            )
            return user

    logger.warning(
        f"❌ [AUTH 401] {request.method} {request.url.path} (от {client_ip}): "
        f"токен '{token_preview}' [{source}] отсутствует в базе данных gateway.db (токен не зарегистрирован или был отозван)"
    )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=f"Токен '{token_preview}' не найден в базе данных. Переавторизуйтесь в настройках ноды.",
        headers={"WWW-Authenticate": "Bearer"},
    )


# =====================================================================
# 3. YANDEX DIALOGS CALLBACKS (Асинхронные уведомления)
# =====================================================================
_pending_state_tasks: Dict[str, asyncio.Task] = {}


async def notify_yandex_discovery(yandex_uid: str, devices: List[dict]):
    """Оповещает Яндекс об изменении списка устройств конкретного пользователя."""
    if not SKILLS_ID or not SKILL_OAUTH_TOKEN:
        return
    try:
        url = f"https://dialogs.yandex.net/api/v1/skills/{SKILLS_ID}/callback/discovery"
        headers = {
            "Authorization": SKILL_OAUTH_TOKEN,
            "Content-Type": "application/json"
        }
        payload = {
            "ts": int(time.time()),
            "payload": {
                "user_id": str(yandex_uid),
                "devices": devices
            }
        }
        def _send():
            return yandex_session.post(url, headers=headers, json=payload, timeout=(3.0, 5.0))
        resp = await asyncio.to_thread(_send)
        logger.info(f"Yandex discovery callback sent для user {yandex_uid}, status: {resp.status_code}")
    except Exception as e:
        logger.warning(f"Ошибка отправки Yandex discovery callback: {e}")


async def notify_yandex_state(yandex_uid: str, dev_id: str, caps: Optional[list] = None, props: Optional[list] = None):
    """Оповещает Яндекс об изменении состояния устройства с дебаунсом 150 мс."""
    if not SKILLS_ID or not SKILL_OAUTH_TOKEN:
        return

    key = f"{yandex_uid}:{dev_id}"
    old_task = _pending_state_tasks.get(key)
    if old_task and not old_task.done():
        old_task.cancel()

    async def _debounced():
        await asyncio.sleep(0.15)
        try:
            url = f"https://dialogs.yandex.net/api/v1/skills/{SKILLS_ID}/callback/state"
            headers = {
                "Authorization": SKILL_OAUTH_TOKEN,
                "Content-Type": "application/json"
            }
            payload = {
                "ts": int(time.time()),
                "payload": {
                    "user_id": str(yandex_uid),
                    "devices": [{
                        "id": dev_id,
                        "capabilities": caps or [],
                        "properties": props or []
                    }]
                }
            }
            def _send():
                return yandex_session.post(url, headers=headers, json=payload, timeout=(3.0, 5.0))

            resp = await asyncio.to_thread(_send)
            logger.info(f"Yandex state callback sent для user {yandex_uid}, dev {dev_id}, status: {resp.status_code}")
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.warning(f"Ошибка отправки Yandex state callback: {e}")
        finally:
            _pending_state_tasks.pop(key, None)

    task = asyncio.create_task(_debounced())
    _pending_state_tasks[key] = task


# =====================================================================
# 4. МЕНЕДЖЕР WEBSOCKET С ИЗОЛЯЦИЕЙ ПО USER_ID
# =====================================================================
class ConnectionManager:
    def __init__(self):
        # user_id (int) -> Set[WebSocket]
        self.active_connections: Dict[int, Set[WebSocket]] = {}
        # key: "{user_id}:{dev_id}:{req_id}" -> Future
        self.pending_commands: Dict[str, asyncio.Future] = {}

    async def connect(self, websocket: WebSocket, user_id: int):
        await websocket.accept()
        if user_id not in self.active_connections:
            self.active_connections[user_id] = set()
        self.active_connections[user_id].add(websocket)
        logger.info(f"Node-RED WS client подключен для user_id={user_id}")
        await websocket.send_text(json.dumps({"v": 1, "type": "hello"}))

    def disconnect(self, websocket: WebSocket, user_id: int):
        if user_id in self.active_connections:
            self.active_connections[user_id].discard(websocket)
            if not self.active_connections[user_id]:
                del self.active_connections[user_id]
        logger.info(f"Node-RED WS client отключен для user_id={user_id}")

    def get_online_counts(self) -> Dict[int, int]:
        """Возвращает user_id -> количество активных сокетов."""
        return {uid: len(sockets) for uid, sockets in self.active_connections.items()}

    def get_total_online(self) -> int:
        """Возвращает общее количество активных сокетов Node-RED."""
        return sum(len(sockets) for sockets in self.active_connections.values())

    async def disconnect_user_sockets(self, user_id: int):
        """Принудительно разрывает все активные WebSocket-соединения пользователя при логауте."""
        sockets = self.active_connections.get(user_id, set())
        for ws in list(sockets):
            try:
                await ws.close(code=4401, reason="Logged out")
            except Exception:
                pass
        self.active_connections.pop(user_id, None)
        logger.info(f"Все сокеты пользователя user_id={user_id} закрыты (Logout)")

    async def broadcast_command(
        self,
        user_id: int,
        dev_id: str,
        payload: list,
        req_id: str,
        timeout: float = 1.5
    ) -> Optional[dict]:
        sockets = self.active_connections.get(user_id, set())
        if not sockets:
            logger.warning(f"Нет активных сокетов Node-RED для user_id={user_id}")
            return None

        frame = json.dumps({
            "v": 1,
            "type": "command",
            "reqId": req_id,
            "devId": dev_id,
            "payload": payload
        })

        loop = asyncio.get_running_loop()
        future = loop.create_future()
        future_key = f"{user_id}:{dev_id}:{req_id}"
        self.pending_commands[future_key] = future

        dead_sockets = set()
        for sock in list(sockets):
            try:
                await sock.send_text(frame)
            except Exception as e:
                logger.error(f"Ошибка отправки кадра в сокет: {e}")
                dead_sockets.add(sock)

        for s in dead_sockets:
            self.disconnect(s, user_id)

        try:
            result = await asyncio.wait_for(future, timeout=timeout)
            return result
        except asyncio.TimeoutError:
            return None
        finally:
            self.pending_commands.pop(future_key, None)

    def resolve_command_result(self, user_id: int, dev_id: str, payload: Any):
        prefix = f"{user_id}:{dev_id}:"
        for key, fut in list(self.pending_commands.items()):
            if key.startswith(prefix) and not fut.done():
                fut.set_result(payload)


manager = ConnectionManager()


async def ws_ping_loop(websocket: WebSocket):
    try:
        while True:
            await asyncio.sleep(30)
            await websocket.send_text(json.dumps({"v": 1, "type": "ping"}))
    except (asyncio.CancelledError, Exception):
        pass


@app.websocket("/v1/ws")
async def websocket_gateway(websocket: WebSocket):
    """
    WebSocket эндпоинт для подключения node-red-contrib-alice.
    Идентифицирует пользователя по Bearer-токену в заголовке Authorization.
    """
    auth_header = websocket.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        await websocket.close(code=4401, reason="Unauthorized: Missing Bearer token")
        return

    token = auth_header.split(" ", 1)[1].strip()
    if not token or token == "local-token":
        await websocket.close(code=4401, reason="Unauthorized: Invalid token, authorization required")
        return

    async with async_session() as session:
        user = await get_user_by_token(session, token)

    if not user:
        await websocket.close(code=4401, reason="Unauthorized: Token not found or revoked")
        return

    user_id = user.id
    yandex_uid = user.yandex_uid

    await manager.connect(websocket, user_id)
    ping_task = asyncio.create_task(ws_ping_loop(websocket))

    try:
        while True:
            raw = await websocket.receive_text()
            try:
                frame = json.loads(raw)
            except Exception:
                continue

            frame_type = frame.get("type")
            if frame_type == "command_result":
                dev_id = frame.get("devId")
                payload = frame.get("payload")
                caps = [payload] if isinstance(payload, dict) else (payload if isinstance(payload, list) else None)

                if caps:
                    async with async_session() as session:
                        async with session.begin():
                            await update_device_states(session, user_id=user_id, dev_id=dev_id, capabilities=caps)

                manager.resolve_command_result(user_id, dev_id, payload)
            elif frame_type == "pong":
                pass
    except WebSocketDisconnect:
        pass
    finally:
        ping_task.cancel()
        manager.disconnect(websocket, user_id)


# =====================================================================
# 5. АВТОРИЗАЦИЯ ИЗ NODE-RED (ОБМЕН VERIFICATION CODE)
# =====================================================================

@app.get("/api/v1/oauth_client_id")
async def get_oauth_client_id():
    """
    Возвращает Client ID приложения Яндекс OAuth из конфигурации шлюза.
    Используется нодой Node-RED для автоматического открытия окна авторизации.
    """
    return {
        "client_id": config.YANDEX_OAUTH_CLIENT_ID or ""
    }


@app.post("/api/v1/getyatoken")
async def exchange_yandex_verification_code(body: dict):
    """
    Вызывается нодой alice-service при нажатии кнопки Submit.
    Обменивает verification_code на access_token в Яндексе,
    создает пользователя в БД и возвращает постоянный токен шлюза для Node-RED.
    """
    code = body.get("code")
    if not code:
        raise HTTPException(status_code=400, detail="Missing verification code")

    # 1. Запрос в Яндекс OAuth на получение access_token пользователя
    token_url = "https://oauth.yandex.ru/token"
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": YANDEX_OAUTH_CLIENT_ID,
        "client_secret": YANDEX_OAUTH_SECRET
    }

    def _send_token_req():
        return yandex_session.post(token_url, data=data, timeout=(4.0, 6.0))

    resp = await asyncio.to_thread(_send_token_req)
    if resp.status_code != 200:
        logger.warning(f"Ошибка обмена кода в Яндекс OAuth: {resp.text}")
        raise HTTPException(status_code=400, detail="Неверный или просроченный код подтверждения")

    yandex_access_token = resp.json().get("access_token")

    # 2. Запрос профиля пользователя в login.yandex.ru
    def _send_info_req():
        return yandex_session.get(
            "https://login.yandex.ru/info",
            headers={"Authorization": f"OAuth {yandex_access_token}"},
            timeout=(4.0, 6.0)
        )

    info_resp = await asyncio.to_thread(_send_info_req)
    if info_resp.status_code != 200:
        raise HTTPException(status_code=400, detail="Не удалось получить профиль пользователя")

    user_info = info_resp.json()
    yandex_uid = str(user_info.get("id"))
    user_email = user_info.get("default_email") or f"{yandex_uid}@yandex.ru"
    display_name = user_info.get("display_name") or user_info.get("first_name") or user_email.split("@")[0]

    # 3. Регистрируем или находим пользователя в БД
    gateway_token = f"gtw_{uuid.uuid4()}"

    async with async_session() as session:
        async with session.begin():
            user = await get_or_create_user(session, yandex_uid=yandex_uid, email=user_email, name=display_name)
            await add_user_token(session, user_id=user.id, token=gateway_token, token_type="nodered")

    logger.info(f"Успешная регистрация Node-RED: user={user_email}, yandex_uid={yandex_uid}")

    # 4. Возвращаем JSON в формате, ожидаемом скриптом GetToken в alice.html
    return {
        "email": user_email,
        "id": yandex_uid,
        "password": "",
        "token": {
            "access_token": gateway_token,
            "token_type": "bearer",
            "expires_in": 315360000
        }
    }


@app.post("/api/v1/logout")
async def gtw_logout(request: Request):
    """
    Удаляет конкретный токен Node-RED из базы при выходе из аккаунта.
    Требует обязательной аутентификации реальным токеном gtw_ (в заголовке Bearer или JSON {token}).
    Никаких обходов по email или yandex_uid!
    """
    token = None

    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        cand = auth_header.split(" ", 1)[1].strip()
        if cand and cand.startswith("gtw_"):
            token = cand

    if not token:
        try:
            body = await request.json()
            cand = body.get("token")
            if cand and isinstance(cand, str) and cand.startswith("gtw_"):
                token = cand
        except Exception:
            pass

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Требуется действительный токен авторизации (gtw_...)",
            headers={"WWW-Authenticate": "Bearer"},
        )

    deleted = False
    target_user_id = None

    async with async_session() as session:
        async with session.begin():
            user = await get_user_by_token(session, token)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Токен не найден или уже был удален",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            target_user_id = user.id
            deleted = await delete_token(session, token)

    if target_user_id:
        await manager.disconnect_user_sockets(target_user_id)

    if deleted:
        logger.info(f"Токен Node-RED {token[:12]}... успешно удален из базы (user_id={target_user_id})")
        return {"status": "ok", "message": "Токен успешно удален"}

    return {"status": "ok", "message": "Токен не найден или уже удален"}


@app.api_route("/payment/getsubscribestatus", methods=["GET", "POST"])
async def gtw_subscription_status():
    """Бесплатный статус подписки для ноды."""
    return {"data": {"text": "Активна"}}


# =====================================================================
# 6. HTTP ЭНДПОИНТЫ УСТРОЙСТВ ДЛЯ NODE-RED
# =====================================================================

@app.post("/gtw/device/config")
async def gtw_device_config(request: Request, user: User = Depends(get_current_user_obj)):
    """Регистрация, обновление или удаление устройства пользователя."""
    body = await request.json()
    dev_id = body.get("id")
    config = body.get("config", {})

    if not dev_id:
        return {"status": "error", "message": "Missing device id"}

    caps = config.get("capabilities", [])
    props = config.get("properties", [])

    async with async_session() as session:
        async with session.begin():
            # Если списки умений и свойств пустые — удаление устройства
            if len(caps) == 0 and len(props) == 0:
                await delete_device(session, user_id=user.id, dev_id=dev_id)
                all_devs = await get_user_devices(session, user_id=user.id)
                logger.info(f"Устройство {dev_id} удалено для user_id={user.id}")
                asyncio.create_task(notify_yandex_discovery(user.yandex_uid, all_devs))
                return {"status": "ok", "deleted": True}

            saved = await save_or_update_device(session, user_id=user.id, dev_id=dev_id, config=config)
            all_devs = await get_user_devices(session, user_id=user.id)

    logger.info(f"Устройство {dev_id} ({config.get('name')}) сохранено для user_id={user.id}")
    asyncio.create_task(notify_yandex_discovery(user.yandex_uid, all_devs))
    return {"status": "ok"}


@app.post("/gtw/device/state")
async def gtw_device_state(request: Request, user: User = Depends(get_current_user_obj)):
    """Обновление состояний умений или датчиков устройства из Node-RED."""
    body = await request.json()
    dev_id = body.get("id")
    state = body.get("state", {})

    caps = state.get("capabilities", [])
    props = state.get("properties", [])

    async with async_session() as session:
        async with session.begin():
            updated, dev_dict = await update_device_states(
                session,
                user_id=user.id,
                dev_id=dev_id,
                capabilities=caps,
                properties=props
            )

    if updated:
        asyncio.create_task(notify_yandex_state(user.yandex_uid, dev_id, caps, props))

    return {"status": "ok"}


@app.api_route("/gtw/device/clearallconfigs", methods=["GET", "POST"])
async def gtw_clear_all_configs(user: User = Depends(get_current_user_obj)):
    """
    Очистка всех устройств пользователя.
    Доступна строго по Bearer-токену аутентифицированного пользователя.
    Никаких обходов по email или yandex_uid!
    """
    async with async_session() as session:
        async with session.begin():
            await clear_user_devices(session, user_id=user.id)

    logger.info(f"Все устройства пользователя user_id={user.id} ({user.email}) успешно очищены")
    asyncio.create_task(notify_yandex_discovery(user.yandex_uid, []))
    return {"status": "ok", "message": "Все устройства успешно удалены"}


# =====================================================================
# 7. OAUTH 2.0 (СВЯЗКА АККАУНТОВ ДЛЯ ПРИЛОЖЕНИЯ «ДОМ С АЛИСОЙ»)
# =====================================================================

@app.get("/auth")
async def auth_from_dialogs(
    client_id: str,
    response_type: str,
    redirect_uri: str,
    state: str
):
    """Шаг 1: Алиса перенаправляет пользователя на наш сервер для связки аккаунтов."""
    session_id = str(uuid.uuid4())
    auth_sessions[session_id] = {
        "redirect_uri": redirect_uri,
        "state": state
    }

    yandex_login_url = (
        f"https://oauth.yandex.ru/authorize"
        f"?response_type=code"
        f"&client_id={YANDEX_OAUTH_CLIENT_ID}"
        f"&state={session_id}"
        f"&force_confirm=yes"
    )
    return RedirectResponse(yandex_login_url)


@app.get("/yandex_callback")
async def callback_from_yandex(code: str, state: str):
    """Шаг 2: Пользователь вошел в Яндекс, Яндекс вернул его с кодом к нам."""
    session = auth_sessions.pop(state, None)
    if not session:
        raise HTTPException(status_code=400, detail="OAuth session expired or not found")

    token_url = "https://oauth.yandex.ru/token"
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": YANDEX_OAUTH_CLIENT_ID,
        "client_secret": YANDEX_OAUTH_SECRET
    }
    def _send_code():
        return yandex_session.post(token_url, data=data, timeout=(4.0, 6.0))
    resp = await asyncio.to_thread(_send_code)
    if resp.status_code != 200:
        raise HTTPException(status_code=400, detail="Failed to get Yandex token")

    yandex_access_token = resp.json().get("access_token")

    def _send_info():
        return yandex_session.get(
            "https://login.yandex.ru/info",
            headers={"Authorization": f"OAuth {yandex_access_token}"},
            timeout=(4.0, 6.0)
        )
    info_resp = await asyncio.to_thread(_send_info)
    if info_resp.status_code != 200:
        raise HTTPException(status_code=400, detail="Failed to fetch user profile")

    user_info = info_resp.json()
    yandex_uid = str(user_info.get("id"))
    user_email = user_info.get("default_email") or f"{yandex_uid}@yandex.ru"
    display_name = user_info.get("display_name") or user_info.get("first_name") or user_email.split("@")[0]

    my_auth_code = str(uuid.uuid4())
    auth_codes[my_auth_code] = {
        "yandex_uid": yandex_uid,
        "email": user_email,
        "name": display_name
    }

    redirect_to_alice = f"{session['redirect_uri']}?code={my_auth_code}&state={session['state']}"
    return RedirectResponse(redirect_to_alice)


@app.post("/token")
async def exchange_token(
    grant_type: str = Form(...),
    code: Optional[str] = Form(None),
    refresh_token: Optional[str] = Form(None),
    client_id: Optional[str] = Form(None),
    client_secret: Optional[str] = Form(None)
):
    """
    Шаг 3: Сервер Алисы меняет выданный временный код на постоянный токен.
    Поддерживает grant_type: authorization_code и refresh_token.
    """
    if grant_type == "refresh_token":
        # Яндекс Диалоги периодически обновляет токен через refresh_token
        if not refresh_token:
            raise HTTPException(status_code=400, detail="Missing refresh_token")

        new_access_token = f"yash_{uuid.uuid4()}"
        new_refresh_token = f"yref_{uuid.uuid4()}"

        async with async_session() as session:
            async with session.begin():
                token_row = await get_token_by_refresh(session, refresh_token)
                if not token_row:
                    raise HTTPException(status_code=400, detail="Invalid or expired refresh_token")
                await rotate_token(session, token_row, new_access_token, new_refresh_token)

        logger.info(f"Токен Яндекс Умного Дома обновлён через refresh_token")

        return {
            "access_token": new_access_token,
            "token_type": "bearer",
            "expires_in": 315360000,
            "refresh_token": new_refresh_token
        }

    # grant_type == "authorization_code"
    if not code or code not in auth_codes:
        raise HTTPException(status_code=400, detail="Invalid or expired authorization code")

    user_data = auth_codes.pop(code)
    smart_home_token = f"yash_{uuid.uuid4()}"
    new_refresh_token = f"yref_{uuid.uuid4()}"

    async with async_session() as session:
        async with session.begin():
            user = await get_or_create_user(
                session,
                yandex_uid=user_data["yandex_uid"],
                email=user_data["email"],
                name=user_data["name"]
            )
            token_row = await add_user_token(
                session,
                user_id=user.id,
                token=smart_home_token,
                token_type="yandex_dialogs"
            )
            token_row.refresh_token = new_refresh_token
            await session.flush()

    logger.info(f"Выпущен токен Яндекс Умного Дома для пользователя {user_data['email']}")

    return {
        "access_token": smart_home_token,
        "token_type": "bearer",
        "expires_in": 315360000,
        "refresh_token": new_refresh_token
    }


# =====================================================================
# 8. РУЧКИ ПРОВАЙДЕРА УМНОГО ДОМА ЯНДЕКСА (/v1.0)
# =====================================================================

@app.head("/v1.0")
@app.get("/v1.0")
async def ping():
    return "OK"


@app.post("/v1.0/user/unlink")
async def unlink(request: Request, user: User = Depends(get_current_user_obj)):
    request_id = request.headers.get("x-request-id", "unknown")
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.split(" ", 1)[1].strip() if " " in auth_header else ""

    if token:
        async with async_session() as session:
            async with session.begin():
                from sqlalchemy import delete as sql_delete
                await session.execute(sql_delete(Token).where(Token.token == token))

    return {"request_id": request_id}


@app.get("/v1.0/user/devices")
async def get_devices(request: Request, user: User = Depends(get_current_user_obj)):
    """Отдает список всех устройств конкретного пользователя."""
    request_id = request.headers.get("x-request-id", "unknown")

    async with async_session() as session:
        user_devices = await get_user_devices(session, user_id=user.id)

    return {
        "request_id": request_id,
        "payload": {
            "user_id": user.yandex_uid,
            "devices": user_devices
        }
    }


@app.post("/v1.0/user/devices/query")
async def query_devices(request: Request, user: User = Depends(get_current_user_obj)):
    """Опрос текущих состояний устройств пользователя."""
    request_id = request.headers.get("x-request-id", "unknown")
    body = await request.json()
    requested_devices = body.get("devices", [])
    req_ids = [d.get("id") for d in requested_devices if d.get("id")]

    async with async_session() as session:
        user_devices = await get_user_devices_query(session, user_id=user.id, dev_ids=req_ids if req_ids else None)

    devices_map = {dev["id"]: dev for dev in user_devices}

    response_devices = []
    for req_dev in requested_devices:
        dev_id = req_dev.get("id")
        if dev_id in devices_map:
            response_devices.append(devices_map[dev_id])
        else:
            response_devices.append({
                "id": dev_id,
                "error_code": "DEVICE_NOT_FOUND",
                "error_message": "Device not found"
            })

    return {
        "request_id": request_id,
        "payload": {
            "devices": response_devices
        }
    }


@app.post("/v1.0/user/devices/action")
async def action_devices(request: Request, user: User = Depends(get_current_user_obj)):
    """
    Выполнение команд от Алисы.
    Команда отправляется в WebSocket строго тому пользователю, кому принадлежит устройство.
    """
    request_id = request.headers.get("x-request-id", "unknown")
    body = await request.json()
    action_devices_list = body.get("payload", {}).get("devices", [])

    async with async_session() as session:
        user_devices = await get_user_devices(session, user_id=user.id)

    devices_map = {d["id"]: d for d in user_devices}
    results = []

    for action_dev in action_devices_list:
        dev_id = action_dev["id"]
        db_dev = devices_map.get(dev_id)

        if db_dev:
            incoming_caps = action_dev.get("capabilities", [])

            # Отправляем команду по WebSocket в Node-RED этого пользователя
            await manager.broadcast_command(
                user_id=user.id,
                dev_id=dev_id,
                payload=incoming_caps,
                req_id=request_id,
                timeout=1.5
            )

            # Обновляем локальное состояние в базе
            async with async_session() as session:
                async with session.begin():
                    await update_device_states(
                        session,
                        user_id=user.id,
                        dev_id=dev_id,
                        capabilities=incoming_caps
                    )

            updated_caps = []
            for action_cap in incoming_caps:
                cap_type = action_cap.get("type")
                cap_instance = action_cap.get("state", {}).get("instance")
                updated_caps.append({
                    "type": cap_type,
                    "state": {
                        "instance": cap_instance,
                        "action_result": {"status": "DONE"}
                    }
                })

            results.append({
                "id": dev_id,
                "capabilities": updated_caps
            })
        else:
            results.append({
                "id": dev_id,
                "action_result": {
                    "status": "ERROR",
                    "error_code": "DEVICE_NOT_FOUND"
                }
            })

    return {
        "request_id": request_id,
        "payload": {
            "devices": results
        }
    }


@app.get("/")
async def gateway_root():
    """Публичный корень шлюза — безопасный статус (панель управления вынесена на порт 5001)."""
    return {"status": "ok", "service": "Yandex Smart Home Gateway"}


# =====================================================================
# 8. ВЕБ-ПАНЕЛЬ УПРАВЛЕНИЯ И МОНИТОРИНГА (ОТДЕЛЬНЫЙ ПОРТ 5001)
# =====================================================================

DASHBOARD_HTML_PATH = config.DASHBOARD_HTML_PATH

dashboard_app = FastAPI(title="Yandex Smart Home Gateway Dashboard")

dashboard_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@dashboard_app.get("/", response_class=HTMLResponse)
async def dashboard_page():
    """Веб-панель управления и статистики (доступна локально на порту 5001)."""
    if os.path.exists(DASHBOARD_HTML_PATH):
        with open(DASHBOARD_HTML_PATH, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Панель управления шлюзом</h1><p>Файл dashboard.html не найден.</p>"


@dashboard_app.get("/api/admin/data")
async def admin_get_data():
    """API для получения данных мониторинга пользователей, токенов и устройств."""
    now = time.time()
    uptime_sec = now - SERVER_START_TIME
    online_counts = manager.get_online_counts()

    async with async_session() as session:
        users = await get_all_users_details(session)

    total_tokens = 0
    total_devices = 0
    for u in users:
        u_id = u["id"]
        u["online_sockets"] = online_counts.get(u_id, 0)
        u["is_online"] = u["online_sockets"] > 0
        total_tokens += len(u.get("tokens", []))
        total_devices += len(u.get("devices", []))

    return {
        "server": {
            "uptime_seconds": int(uptime_sec),
            "uptime_str": format_uptime(uptime_sec),
            "total_online_sockets": manager.get_total_online(),
            "total_users": len(users),
            "total_tokens": total_tokens,
            "total_devices": total_devices,
            "skill_id": SKILLS_ID
        },
        "users": users
    }


@dashboard_app.delete("/api/admin/tokens/{token}")
async def admin_delete_token(token: str):
    """Отозвать и удалить токен авторизации."""
    async with async_session() as session:
        async with session.begin():
            deleted = await delete_token(session, token)

    if deleted:
        logger.info(f"Токен {token[:12]}... успешно отозван через веб-панель")
        return {"status": "ok", "message": "Токен успешно отозван"}

    raise HTTPException(status_code=404, detail="Токен не найден")


@dashboard_app.delete("/api/admin/devices/{user_id}/{dev_id}")
async def admin_delete_device(user_id: int, dev_id: str):
    """Удалить устройство пользователя с сервера и уведомить Яндекс."""
    async with async_session() as session:
        async with session.begin():
            user_stmt = select(User).where(User.id == user_id)
            user_res = await session.execute(user_stmt)
            user = user_res.scalar_one_or_none()
            if not user:
                raise HTTPException(status_code=404, detail="Пользователь не найден")

            await delete_device(session, user_id=user_id, dev_id=dev_id)
            remaining_devices = await get_user_devices(session, user_id=user_id)

    asyncio.create_task(notify_yandex_discovery(user.yandex_uid, remaining_devices))
    logger.info(f"Устройство {dev_id} удалено через веб-панель для user_id={user_id}")
    return {"status": "ok", "message": f"Устройство {dev_id} успешно удалено"}


@dashboard_app.delete("/api/admin/users/{user_id}/devices")
async def admin_clear_all_user_devices(user_id: int):
    """Удалить все устройства конкретного пользователя и уведомить Яндекс."""
    async with async_session() as session:
        async with session.begin():
            user_stmt = select(User).where(User.id == user_id)
            user_res = await session.execute(user_stmt)
            user = user_res.scalar_one_or_none()
            if not user:
                raise HTTPException(status_code=404, detail="Пользователь не найден")

            await clear_user_devices(session, user_id=user.id)

    asyncio.create_task(notify_yandex_discovery(user.yandex_uid, []))
    logger.info(f"Все устройства пользователя user_id={user_id} ({user.email}) удалены через веб-панель")
    return {"status": "ok", "message": f"Все устройства пользователя {user.email} успешно удалены"}


@dashboard_app.delete("/api/admin/users/{user_id}")
async def admin_delete_user_account(user_id: int):
    """
    Полностью удалить аккаунт пользователя, все его токены,
    все виртуальные устройства и запись пользователя из базы данных.
    Также уведомляет Яндекс Диалоги об удалении устройств.
    """
    await manager.disconnect_user_sockets(user_id)
    async with async_session() as session:
        async with session.begin():
            success, yandex_uid, email = await delete_user_account(session, user_id=user_id)
            if not success:
                raise HTTPException(status_code=404, detail="Пользователь не найден")

    if yandex_uid:
        asyncio.create_task(notify_yandex_discovery(yandex_uid, []))

    logger.info(f"Аккаунт пользователя user_id={user_id} ({email}, UID: {yandex_uid}) полностью удален со всеми устройствами и токенами")
    return {"status": "ok", "message": f"Аккаунт {email} со всеми токенами и устройствами успешно удален"}


async def run_servers():
    """Запуск обоих серверов (шлюз на порту 5000, веб-панель на порту 5001) в одном event loop."""
    config_gateway = uvicorn.Config(
        app,
        host=config.GATEWAY_HOST,
        port=config.GATEWAY_PORT,
        log_level=config.LOG_LEVEL.lower()
    )
    config_dashboard = uvicorn.Config(
        dashboard_app,
        host=config.DASHBOARD_HOST,
        port=config.DASHBOARD_PORT,
        log_level=config.LOG_LEVEL.lower()
    )

    server_gateway = uvicorn.Server(config_gateway)
    server_dashboard = uvicorn.Server(config_dashboard)

    logger.info(f"Шлюз умного дома запущен на http://{config.GATEWAY_HOST}:{config.GATEWAY_PORT}")
    logger.info(f"Панель управления запущена на http://{config.DASHBOARD_HOST}:{config.DASHBOARD_PORT}")

    try:
        await asyncio.gather(
            server_gateway.serve(),
            server_dashboard.serve()
        )
    except (asyncio.CancelledError, KeyboardInterrupt):
        logger.info("Серверы корректно остановлены.")


if __name__ == "__main__":
    try:
        asyncio.run(run_servers())
    except (KeyboardInterrupt, SystemExit):
        logger.info("Выход из приложения.")
