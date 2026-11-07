FROM python:3.11-slim
# Установка curl для healthcheck и tzdata для времени
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    tzdata \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# Кэширование слоя зависимостей Python
COPY Server/requirements.txt* requirements.txt* ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt
# Копирование исходного кода сервера в /app
COPY Server/ /app/
# Создание директории данных
RUN mkdir -p /data
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DATA_DIR=/data
# 5000: Порт для Яндекс Диалогов и WebSocket Node-RED
# 5001: Веб-панель администратора
EXPOSE 5000 5001
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/ || exit 1
CMD ["python", "main.py"]