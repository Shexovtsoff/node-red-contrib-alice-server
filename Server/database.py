import asyncio
from datetime import datetime
import json
import logging
import os
from typing import Dict, Any, Optional, List, Tuple

from sqlalchemy import (
    String,
    Integer,
    Text,
    DateTime,
    ForeignKey,
    select,
    delete,
    update,
    text
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship
)
from sqlalchemy.ext.asyncio import (
    create_async_engine,
    async_sessionmaker,
    AsyncSession
)

import config

try:
    from Server.yandex_specs import YandexSpecHandler
except ImportError:
    from yandex_specs import YandexSpecHandler

logger = logging.getLogger("smart_home_gateway.db")

DATABASE_URL = config.DATABASE_URL
engine = create_async_engine(DATABASE_URL, echo=False)
async_session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    yandex_uid: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(128), index=True)
    name: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    tokens: Mapped[List["Token"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="selectin"
    )
    devices: Mapped[List["Device"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="selectin"
    )


class Token(Base):
    __tablename__ = "tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    token_type: Mapped[str] = mapped_column(String(32))  # 'nodered' или 'yandex_dialogs'
    refresh_token: Mapped[Optional[str]] = mapped_column(String(128), unique=True, index=True, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    user: Mapped["User"] = relationship(back_populates="tokens")


class Device(Base):
    __tablename__ = "devices"

    # Составной первичный ключ: (id ноды, user_id)
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True, index=True)

    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(String(256), default="")
    room: Mapped[str] = mapped_column(String(128), default="")
    type: Mapped[str] = mapped_column(String(64), default="devices.types.other")

    custom_data_json: Mapped[str] = mapped_column(Text, default="{}")
    device_info_json: Mapped[str] = mapped_column(Text, default="{}")
    capabilities_json: Mapped[str] = mapped_column(Text, default="[]")
    properties_json: Mapped[str] = mapped_column(Text, default="[]")

    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user: Mapped["User"] = relationship(back_populates="devices")

    def to_yandex_discovery_dict(self) -> dict:
        """Форматирует устройство строго по схеме Яндекс Умного Дома для Discovery (GET /v1.0/user/devices).
        В ответе Discovery НЕ ДОЛЖНО быть полей state и внутренних id нод!"""
        try:
            custom_data = json.loads(self.custom_data_json)
        except Exception:
            custom_data = {}

        try:
            device_info = json.loads(self.device_info_json)
        except Exception:
            device_info = {
                "manufacturer": "NodeRed Home",
                "model": "virtual device",
                "sw_version": "3.0.4"
            }

        try:
            raw_caps = json.loads(self.capabilities_json)
        except Exception:
            raw_caps = []

        try:
            raw_props = json.loads(self.properties_json)
        except Exception:
            raw_props = []

        clean_capabilities = []
        for cap in raw_caps:
            norm = YandexSpecHandler.normalize_capability_discovery(cap)
            if norm:
                clean_capabilities.append(norm)

        clean_properties = []
        for prop in raw_props:
            norm = YandexSpecHandler.normalize_property_discovery(prop)
            if norm:
                clean_properties.append(norm)

        res = {
            "id": str(self.id),
            "name": self.name or "Устройство",
            "type": self.type or "devices.types.other",
            "capabilities": clean_capabilities,
            "properties": clean_properties
        }
        if self.description:
            res["description"] = self.description
        if self.room:
            res["room"] = self.room
        if custom_data:
            res["custom_data"] = custom_data
        if device_info:
            res["device_info"] = device_info

        return res

    def to_yandex_query_dict(self) -> dict:
        """Форматирует устройство для опроса состояний (POST /v1.0/user/devices/query).
        Строго по спецификации Яндекс УД:
        - Исключаются умения и свойства с retrievable: False
        - Для color_setting инстанс строго один из: rgb, temperature_k, hsv, scene
        - Строгая типизация значений (bool для on_off/toggle, int/float для range, str для mode/event)
        """
        try:
            raw_caps = json.loads(self.capabilities_json)
        except Exception:
            raw_caps = []

        try:
            raw_props = json.loads(self.properties_json)
        except Exception:
            raw_props = []

        caps_state = []
        for c in raw_caps:
            norm = YandexSpecHandler.normalize_capability_query_state(c)
            if norm:
                caps_state.append(norm)

        props_state = []
        for p in raw_props:
            norm = YandexSpecHandler.normalize_property_query_state(p)
            if norm:
                props_state.append(norm)

        res = {"id": str(self.id)}
        if caps_state:
            res["capabilities"] = caps_state
        if props_state:
            res["properties"] = props_state
        if not caps_state and not props_state:
            res["capabilities"] = []
        return res

    def to_dashboard_dict(self) -> dict:
        """Форматирует устройство для отображения в веб-панели управления."""
        try:
            capabilities = json.loads(self.capabilities_json)
        except Exception:
            capabilities = []
        try:
            properties = json.loads(self.properties_json)
        except Exception:
            properties = []

        return {
            "id": str(self.id),
            "name": self.name,
            "description": self.description,
            "room": self.room,
            "type": self.type,
            "capabilities": capabilities,
            "properties": properties
        }

    def to_yandex_dict(self) -> dict:
        """По умолчанию отдает чистую спецификацию для Discovery."""
        return self.to_yandex_discovery_dict()


# =====================================================================
# ОПЕРАЦИИ С БАЗОЙ ДАННЫХ
# =====================================================================

async def init_db():
    """Создает таблицы в базе данных SQLite и мигрирует схему при необходимости."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

        # Миграция: добавляем refresh_token в таблицу tokens, если колонки нет
        try:
            result = await conn.execute(text("PRAGMA table_info(tokens)"))
            columns = [row[1] for row in result.fetchall()]
            if "refresh_token" not in columns:
                await conn.execute(text("ALTER TABLE tokens ADD COLUMN refresh_token VARCHAR(128)"))
                logger.info("Миграция: добавлена колонка refresh_token в таблицу tokens")
        except Exception as e:
            logger.warning(f"Миграция refresh_token: {e}")


async def get_or_create_user(session: AsyncSession, yandex_uid: str, email: str, name: Optional[str] = None) -> User:
    """Находит пользователя по yandex_uid или создает нового."""
    stmt = select(User).where(User.yandex_uid == str(yandex_uid))
    res = await session.execute(stmt)
    user = res.scalar_one_or_none()

    if not user:
        # Также проверяем по email на случай смены UID
        stmt_email = select(User).where(User.email == email)
        res_email = await session.execute(stmt_email)
        user = res_email.scalar_one_or_none()

    if not user:
        user = User(
            yandex_uid=str(yandex_uid),
            email=email,
            name=name or email.split("@")[0]
        )
        session.add(user)
        await session.flush()
    else:
        # Обновляем email / name, если изменились
        user.yandex_uid = str(yandex_uid)
        user.email = email
        if name:
            user.name = name
        await session.flush()

    return user


async def add_user_token(session: AsyncSession, user_id: int, token: str, token_type: str, max_tokens: Optional[int] = None) -> Token:
    """Сохраняет токен авторизации (Node-RED или Яндекс Диалогов) с поддержкой до max_tokens активных токенов."""
    if max_tokens is None:
        max_tokens = config.MAX_USER_TOKENS
    if token_type == "nodered":
        # Получаем список nodered токенов пользователя от старых к новым
        stmt = (
            select(Token)
            .where(Token.user_id == user_id, Token.token_type == "nodered")
            .order_by(Token.created_at.asc(), Token.id.asc())
        )
        res = await session.execute(stmt)
        existing = list(res.scalars().all())

        # Если количество активных токенов достигло лимита (по умолчанию 5), удаляем самые старые
        while len(existing) >= max_tokens:
            oldest = existing.pop(0)
            await session.delete(oldest)
    else:
        # Для Yandex Skill OAuth токен единственный на аккаунт — заменяем старый токен навыка этого пользователя
        await session.execute(
            delete(Token).where(Token.user_id == user_id, Token.token_type == token_type)
        )

    new_token = Token(user_id=user_id, token=token, token_type=token_type)
    session.add(new_token)
    await session.flush()
    return new_token


async def get_all_users_details(session: AsyncSession) -> List[dict]:
    """Возвращает детальную информацию по всем пользователям, токенам и устройствам для веб-панели."""
    stmt = select(User).order_by(User.id.asc())
    res = await session.execute(stmt)
    users = res.scalars().all()

    result = []
    for u in users:
        t_stmt = select(Token).where(Token.user_id == u.id).order_by(Token.created_at.desc())
        t_res = await session.execute(t_stmt)
        tokens = t_res.scalars().all()

        d_stmt = select(Device).where(Device.user_id == u.id).order_by(Device.name.asc())
        d_res = await session.execute(d_stmt)
        devices = d_res.scalars().all()

        nodered_count = len([t for t in tokens if t.token_type == "nodered"])

        result.append({
            "id": u.id,
            "yandex_uid": u.yandex_uid,
            "email": u.email,
            "name": u.name,
            "created_at": u.created_at.strftime("%Y-%m-%d %H:%M:%S") if u.created_at else "",
            "nodered_tokens_count": nodered_count,
            "tokens": [
                {
                    "id": t.id,
                    "token": t.token,
                    "token_type": t.token_type,
                    "created_at": t.created_at.strftime("%Y-%m-%d %H:%M:%S") if t.created_at else ""
                }
                for t in tokens
            ],
            "devices": [d.to_dashboard_dict() for d in devices]
        })
    return result


async def delete_token(session: AsyncSession, token: str) -> bool:
    """Удаляет конкретный токен авторизации (например при логауте из Node-RED)."""
    res = await session.execute(delete(Token).where(Token.token == token))
    return res.rowcount > 0


async def get_token_by_refresh(session: AsyncSession, ref_token: str) -> Optional[Token]:
    """Находит запись Token по значению refresh_token."""
    stmt = select(Token).where(Token.refresh_token == ref_token)
    res = await session.execute(stmt)
    return res.scalar_one_or_none()


async def rotate_token(session: AsyncSession, old_token_row: Token, new_access: str, new_refresh: str) -> Token:
    """Заменяет access_token и refresh_token в существующей записи (ротация при refresh)."""
    old_token_row.token = new_access
    old_token_row.refresh_token = new_refresh
    old_token_row.created_at = datetime.utcnow()
    await session.flush()
    return old_token_row


async def get_user_by_token(session: AsyncSession, token: str) -> Optional[User]:
    """Находит пользователя по Bearer-токену."""
    stmt = select(User).join(Token, Token.user_id == User.id).where(Token.token == token)
    res = await session.execute(stmt)
    return res.scalar_one_or_none()


async def get_user_devices(session: AsyncSession, user_id: int) -> List[dict]:
    """Возвращает список устройств пользователя в формате Яндекс УД для Discovery."""
    stmt = select(Device).where(Device.user_id == user_id)
    res = await session.execute(stmt)
    devices = res.scalars().all()
    return [d.to_yandex_discovery_dict() for d in devices]


async def get_user_devices_query(
    session: AsyncSession,
    user_id: int,
    dev_ids: Optional[List[str]] = None
) -> List[dict]:
    """Возвращает состояния устройств пользователя для ответа на query."""
    if dev_ids:
        stmt = select(Device).where(Device.user_id == user_id, Device.id.in_(dev_ids))
    else:
        stmt = select(Device).where(Device.user_id == user_id)
    res = await session.execute(stmt)
    devices = res.scalars().all()
    return [d.to_yandex_query_dict() for d in devices]


async def save_or_update_device(session: AsyncSession, user_id: int, dev_id: str, config: dict) -> dict:
    """Создает или обновляет устройство пользователя, сохраняя текущие состояния."""
    caps = config.get("capabilities", [])
    props = config.get("properties", [])

    # Инициализация состояний по умолчанию для умений со строгой типизацией
    for cap in caps:
        if "state" not in cap:
            cap_type = cap.get("type", "")
            params = cap.get("parameters", {})
            if cap_type in ("devices.capabilities.on_off", "devices.capabilities.toggle"):
                inst = params.get("instance", "on")
                default_val = False
            elif cap_type == "devices.capabilities.mode":
                inst = params.get("instance", "mode")
                modes = params.get("modes", [])
                default_val = modes[0].get("value") if modes and isinstance(modes[0], dict) else "auto"
            elif cap_type == "devices.capabilities.color_setting":
                if "temperature_k" in params:
                    inst = "temperature_k"
                    t_min = params["temperature_k"].get("min", 2000)
                    t_max = params["temperature_k"].get("max", 9000)
                    default_val = 4500 if t_min <= 4500 <= t_max else t_min
                elif "color_model" in params:
                    cm = params.get("color_model", "rgb")
                    inst = cm
                    default_val = 16777215 if cm == "rgb" else {"h": 0, "s": 0, "v": 100}
                elif "color_scene" in params:
                    inst = "scene"
                    scenes = params.get("color_scene", {}).get("scenes", [])
                    default_val = scenes[0]["id"] if scenes else "alice"
                else:
                    inst = "temperature_k"
                    default_val = 4500
            elif cap_type == "devices.capabilities.range":
                inst = params.get("instance", "brightness")
                range_p = params.get("range", {})
                default_val = range_p.get("min", 0)
            else:
                inst = params.get("instance", "on")
                default_val = 0
            cap["state"] = {"instance": inst, "value": default_val}

    # Инициализация состояний по умолчанию для датчиков со строгой типизацией
    for prop in props:
        if "state" not in prop:
            prop_type = prop.get("type", "")
            inst = prop.get("parameters", {}).get("instance", "temperature")
            if prop_type == "devices.properties.event":
                events = prop.get("parameters", {}).get("events", [])
                default_val = events[0].get("value") if events and isinstance(events[0], dict) else "opened"
            else:
                default_val = 0.0
            prop["state"] = {"instance": inst, "value": default_val}

    stmt = select(Device).where(Device.id == dev_id, Device.user_id == user_id)
    res = await session.execute(stmt)
    device = res.scalar_one_or_none()

    if device:
        # Если устройство уже существует — сохраняем предыдущие значения состояний
        try:
            existing_caps = json.loads(device.capabilities_json)
        except Exception:
            existing_caps = []
        try:
            existing_props = json.loads(device.properties_json)
        except Exception:
            existing_props = []

        for cap in caps:
            cap_type = cap.get("type")
            cap_params = cap.get("parameters", {})
            cap_inst = cap_params.get("instance")

            ex_cap = None
            for c in existing_caps:
                if c.get("type") != cap_type:
                    continue
                c_param_inst = c.get("parameters", {}).get("instance")
                if cap_inst:
                    if c_param_inst == cap_inst:
                        ex_cap = c
                        break
                else:
                    # Для умений без parameters.instance (color_setting, on_off) сопоставляем по type
                    ex_cap = c
                    break

            if ex_cap and "state" in ex_cap:
                ex_st = ex_cap["state"]
                # Валидируем сохраненное состояние color_setting
                if cap_type == "devices.capabilities.color_setting":
                    if isinstance(ex_st, dict) and ex_st.get("instance") in ("rgb", "temperature_k", "hsv", "scene"):
                        cap["state"] = ex_st
                    # Если было невалидное (например "on"), оставляем новое корректное cap["state"]
                else:
                    cap["state"] = ex_st

        for prop in props:
            prop_type = prop.get("type")
            prop_inst = prop.get("parameters", {}).get("instance") or prop.get("state", {}).get("instance")
            ex_prop = next(
                (p for p in existing_props if p.get("type") == prop_type and
                 (p.get("parameters", {}).get("instance") == prop_inst or
                  p.get("state", {}).get("instance") == prop_inst)),
                None
            )
            if ex_prop and "state" in ex_prop:
                prop["state"] = ex_prop["state"]

        device.name = config.get("name") or device.name
        device.description = config.get("description", device.description)
        device.room = config.get("room", device.room)
        device.type = config.get("type", device.type)
        device.custom_data_json = json.dumps(config.get("custom_data", {}))
        device.device_info_json = json.dumps(config.get("device_info", {}))
        device.capabilities_json = json.dumps(caps)
        device.properties_json = json.dumps(props)
        device.updated_at = datetime.utcnow()
    else:
        device = Device(
            id=dev_id,
            user_id=user_id,
            name=config.get("name") or "Устройство",
            description=config.get("description", ""),
            room=config.get("room", ""),
            type=config.get("type", "devices.types.other"),
            custom_data_json=json.dumps(config.get("custom_data", {})),
            device_info_json=json.dumps(config.get("device_info", {})),
            capabilities_json=json.dumps(caps),
            properties_json=json.dumps(props)
        )
        session.add(device)

    await session.flush()
    return device.to_yandex_dict()


async def delete_device(session: AsyncSession, user_id: int, dev_id: str) -> bool:
    """Удаляет устройство пользователя."""
    stmt = delete(Device).where(Device.id == dev_id, Device.user_id == user_id)
    res = await session.execute(stmt)
    await session.flush()
    return res.rowcount > 0


async def clear_user_devices(session: AsyncSession, user_id: int):
    """Очищает все устройства пользователя."""
    stmt = delete(Device).where(Device.user_id == user_id)
    await session.execute(stmt)
    await session.flush()


async def delete_user_account(session: AsyncSession, user_id: int) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Полностью удаляет аккаунт пользователя из БД:
    все устройства, все токены и запись пользователя.
    Возвращает (успех, yandex_uid, email).
    """
    stmt = select(User).where(User.id == user_id)
    res = await session.execute(stmt)
    user = res.scalar_one_or_none()
    if not user:
        return False, None, None

    yandex_uid = user.yandex_uid
    email = user.email

    await session.execute(delete(Device).where(Device.user_id == user_id))
    await session.execute(delete(Token).where(Token.user_id == user_id))
    await session.execute(delete(User).where(User.id == user_id))
    await session.flush()
    return True, yandex_uid, email


async def update_device_states(
    session: AsyncSession,
    user_id: int,
    dev_id: str,
    capabilities: Optional[List[dict]] = None,
    properties: Optional[List[dict]] = None
) -> Tuple[bool, Optional[dict]]:
    """Обновляет значения состояний умений или свойств устройства в БД."""
    stmt = select(Device).where(Device.id == dev_id, Device.user_id == user_id)
    res = await session.execute(stmt)
    device = res.scalar_one_or_none()
    if not device:
        return False, None

    try:
        dev_caps = json.loads(device.capabilities_json)
    except Exception:
        dev_caps = []

    try:
        dev_props = json.loads(device.properties_json)
    except Exception:
        dev_props = []

    if capabilities:
        for inc in capabilities:
            inc_type = inc.get("type")
            inc_state = inc.get("state", {})
            inc_inst = inc_state.get("instance")
            for target in dev_caps:
                if target.get("type") != inc_type:
                    continue
                target_param_inst = target.get("parameters", {}).get("instance")
                # Для range, toggle, mode сопоставляем по instance из parameters
                if target_param_inst and inc_inst and target_param_inst != inc_inst:
                    continue
                # Для color_setting проверяем допустимый инстанс
                if inc_type == "devices.capabilities.color_setting":
                    if inc_inst not in ("rgb", "temperature_k", "hsv", "scene"):
                        continue

                # Поддержка относительного изменения (relative: true) для range
                if inc_type == "devices.capabilities.range" and inc_state.get("relative") is True:
                    curr_v = target.get("state", {}).get("value", 0)
                    r_obj = target.get("parameters", {}).get("range", {})
                    min_v = r_obj.get("min", 0)
                    max_v = r_obj.get("max", 100)
                    try:
                        curr_num = float(curr_v) if ("." in str(curr_v) or isinstance(curr_v, float)) else int(curr_v)
                        delta_num = float(inc_state.get("value", 0)) if ("." in str(inc_state.get("value", 0)) or isinstance(inc_state.get("value", 0), float)) else int(inc_state.get("value", 0))
                        new_val = curr_num + delta_num
                    except Exception:
                        new_val = delta_num
                    if min_v is not None and new_val < min_v:
                        new_val = min_v
                    if max_v is not None and new_val > max_v:
                        new_val = max_v
                    if isinstance(new_val, float) and new_val.is_integer():
                        new_val = int(new_val)
                    target["state"] = {
                        "instance": inc_inst or target_param_inst or "brightness",
                        "value": new_val
                    }
                else:
                    target["state"] = {
                        "instance": inc_inst or target.get("state", {}).get("instance") or target_param_inst or "on",
                        "value": inc_state.get("value")
                    }
                break

    if properties:
        for inc in properties:
            inc_type = inc.get("type")
            inc_state = inc.get("state", {})
            inc_inst = inc_state.get("instance")
            for target in dev_props:
                if target.get("type") != inc_type:
                    continue
                target_param_inst = target.get("parameters", {}).get("instance")
                if target_param_inst and inc_inst and target_param_inst != inc_inst:
                    continue
                target["state"] = {
                    "instance": inc_inst or target.get("state", {}).get("instance") or target_param_inst or "temperature",
                    "value": inc_state.get("value")
                }
                break

    try:
        device.capabilities_json = json.dumps(dev_caps)
        device.properties_json = json.dumps(dev_props)
        device.updated_at = datetime.utcnow()
        await session.flush()
        return True, device.to_yandex_dict()
    except Exception as e:
        logger.warning(f"Ошибка обновления состояния устройства {dev_id}: {e}")
        return False, None
