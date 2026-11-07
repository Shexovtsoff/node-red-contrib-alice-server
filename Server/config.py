import os
import logging
from typing import Optional

# Загрузка переменных окружения из .env файла
try:
    from dotenv import load_dotenv

    # Проверяем наличие .env в текущей директории, в Server/ или в корне проекта
    env_paths = [
        os.path.join(os.getcwd(), ".env"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"),
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"),
    ]
    for p in env_paths:
        if os.path.isfile(p):
            load_dotenv(p)
            break
except ImportError:
    pass

# =====================================================================
# СЕТЕВЫЕ НАСТРОЙКИ
# =====================================================================
GATEWAY_HOST: str = os.getenv("GATEWAY_HOST", "0.0.0.0")
GATEWAY_PORT: int = int(os.getenv("GATEWAY_PORT", "5000"))

DASHBOARD_HOST: str = os.getenv("DASHBOARD_HOST", "0.0.0.0")
DASHBOARD_PORT: int = int(os.getenv("DASHBOARD_PORT", "5001"))

LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()

# =====================================================================
# ХРАНИЛИЩЕ ДАННЫХ И БАЗА ДАННЫХ (DOCKER VOLUME FRIENDLY)
# =====================================================================
# В контейнере монтируется в /data; локально по умолчанию директория Server/
DEFAULT_DATA_DIR = "/data" if os.path.exists("/data") else os.path.dirname(os.path.abspath(__file__))
DATA_DIR: str = os.getenv("DATA_DIR", DEFAULT_DATA_DIR)
os.makedirs(DATA_DIR, exist_ok=True)

DEFAULT_DB_FILE = os.path.join(DATA_DIR, "gateway.db").replace("\\", "/")
DB_PATH: str = os.getenv("DB_PATH", DEFAULT_DB_FILE).replace("\\", "/")
DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite+aiosqlite:///{DB_PATH}")
DASHBOARD_HTML_PATH: str = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "dashboard.html"
)

# Лимит активных токенов Node-RED на одного пользователя
MAX_USER_TOKENS: int = int(os.getenv("MAX_USER_TOKENS", "5"))

# =====================================================================
# ИНТЕГРАЦИЯ С ЯНДЕКСОМ (OAUTH И ДИАЛОГИ)
# =====================================================================
# 1. OAuth приложение разработчика в oauth.yandex.ru
YANDEX_OAUTH_CLIENT_ID: str = os.getenv("YANDEX_OAUTH_CLIENT_ID", "")
YANDEX_OAUTH_SECRET: str = os.getenv("YANDEX_OAUTH_SECRET", "")

# 2. Связка аккаунтов в консоли Яндекс Диалогов
SMART_HOME_CLIENT_ID: str = os.getenv("SMART_HOME_CLIENT_ID", "")
SMART_HOME_CLIENT_SECRET: str = os.getenv("SMART_HOME_CLIENT_SECRET", "")

# 3. Идентификатор навыка и токен для callback-уведомлений Яндекса
YANDEX_SKILLS_ID: str = os.getenv("YANDEX_SKILLS_ID", "")
YANDEX_SKILL_OAUTH_TOKEN: str = os.getenv("YANDEX_SKILL_OAUTH_TOKEN", "")

# Нормализация токена навыка (гарантируем префикс "OAuth ")
if YANDEX_SKILL_OAUTH_TOKEN and not YANDEX_SKILL_OAUTH_TOKEN.startswith("OAuth "):
    YANDEX_SKILL_OAUTH_TOKEN = f"OAuth {YANDEX_SKILL_OAUTH_TOKEN}"
