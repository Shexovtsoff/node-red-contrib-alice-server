from sqlalchemy import insert, select
import uvicorn  # Импортируем Uvicorn для запуска ASGI приложения
import paho.mqtt.client as mqtt  # Импортируем paho-mqtt для работы с MQTT
from fastapi import FastAPI, Request, Form, HTTPException, status, Depends  # Импортируем необходимые модули из FastAPI
from fastapi.responses import RedirectResponse, JSONResponse  # Импортируем классы для ответов из FastAPI
from fastapi.templating import Jinja2Templates  # Импортируем Jinja2Templates для шаблонизации
from fastapi.security import OAuth2PasswordRequestForm  # Импортируем OAuth2PasswordRequestForm для работы с OAuth2
from passlib.context import CryptContext  # Импортируем CryptContext для работы с хэшированием паролей
from pydantic import BaseModel  # Импортируем BaseModel для работы с моделями данных

import random  # Импортируем random для генерации случайных значений
import string  # Импортируем string для работы со строками
import time  # Импортируем time для работы со временем
from loguru import logger  # Импортируем logger из loguru для логирования
from typing import Annotated  # Импортируем Annotated для аннотаций типов
import json  # Импортируем json для работы с JSON данными
import requests  # Импортируем requests для выполнения HTTP запросов

from config import settings  # Импортируем настройки из config.py

from BD import User as DBUser, Device as DBDevice, session_factory, engine

app = FastAPI()  # Создаем экземпляр приложения FastAPI
templates = Jinja2Templates(directory="app/templates")  # Указываем директорию для шаблонов Jinja2
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")  # Создаем контекст для хэширования паролей с использованием bcrypt

# Настройка MQTT клиента
client = mqtt.Client()  # Создаем экземпляр MQTT клиента
client.connect(settings.mqtt_broker, settings.mqtt_port, 60)  # Подключаемся к MQTT брокеру
client.subscribe(settings.mqtt_topic)  # Подписываемся на топик

# Глобальные переменные для хранения последнего кода аутентификации и времени его создания
last_code = ""  
last_code_user = ""  
last_code_time = 0  

# Списки для хранения устройств и событий
devices_list = []  
еvent_list = []
user_uuid = ""

# Обработчик для получения сообщения MQTT
def on_message(client, userdata, message):
    logger.info(message.topic + " / " + message.payload.decode())  # Логируем сообщение
    fmessage(message.topic, message.payload.decode())  # Обрабатываем сообщение

client.on_message = on_message  # Назначаем обработчик сообщений
client.loop_start()  # Запускаем цикл обработки сообщений
# Функция для отказа в доступе
def access_deny():
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,  # Устанавливаем статус код 401
        detail="Invalid authentication credentials",  # Устанавливаем детальное сообщение
        headers={"WWW-Authenticate": "Bearer"},  # Устанавливаем заголовки ответа
    )


# Декоратор для преобразования формы в JSON
def form_body(cls):
    """From body form url to json helper"""
    cls.__signature__ = cls.__signature__.replace(
        parameters=[
            arg.replace(default=Form(...))  # Заменяем параметры на значения формы
            for arg in cls.__signature__.parameters.values()
        ]
    )
    return cls


# Модель данных для получения токена
@form_body
class GetTokenModel(BaseModel):
    code: str  # Поле для кода
    client_secret: str  # Поле для секрета клиента
    grant_type: str  # Поле для типа гранта
    client_id: str  # Поле для идентификатора клиента

# Обработка сообщения MQTT
def fmessage(topic, payload):
    ar_topic = topic.split("/")  # Разделяем топик на части
    device = None
    if payload != "":
        device = json.loads(payload)  # Декодируем payload из JSON
        if len(ar_topic) == 4:
            if ar_topic[2] == "state":
                print(device["id"])
                add = True
                for i in range(0, len(devices_list)):
                    if devices_list[i]["id"] == device["id"]:
                        add = False
                        if devices_list[i] != device:
                            devices_list[i] = device
                            UpdateDevice()
                if add:
                    devices_list.append(device)
                    UpdateDevice()
            elif ar_topic[2] == "events":
                еvent_list.append(json.loads(payload))
        elif len(ar_topic) == 5:
            for i in range(0, len(devices_list)):
                if devices_list[i]["id"] == device["id"]:
                    for j in range(0, len(devices_list[i]["capabilities"])):
                        for k in range(0, len(device["capabilities"])):
                            if (
                                devices_list[i]["capabilities"][j]["id"]
                                == device["capabilities"][k]["id"]
                            ):
                                devices_list[i]["capabilities"][j]["state"] = device[
                                    "capabilities"
                                ][k]["state"]
                    for j in range(0, len(devices_list[i]["properties"])):
                        for k in range(0, len(device["properties"])):
                            if (
                                devices_list[i]["properties"][j]["id"]
                                == device["properties"][k]["id"]
                            ):
                                devices_list[i]["properties"][j]["state"] = device[
                                    "properties"
                                ][k]["state"]
                    UpdateState(devices_list[i])

# Обновление состояния устройства
def UpdateState(Device):
    print("Обновления Свойств")
    result = {"ts": 0, "payload": {"user_id": user_uuid, "devices": []}}
    new_device = {"id": Device["id"], "capabilities": [], "properties": []}
    new_device["capabilities"] = Device["capabilities"]
    new_device["properties"] = Device["properties"]
    result["payload"]["devices"].append(new_device)

    url = f"https://dialogs.yandex.net/api/v1/skills/{settings.skills_id}/callback/state"
    result["ts"] = int(time.time())
    headers = {
        "Authorization": settings.oauth_token,
        "Content-Type": "application/json",
    }
    requests.post(url, headers=headers, data=json.dumps(result))

# Обновление данных устройства
def UpdateDevice():
    result = {"ts": 0, "payload": {"user_id": user_uuid}}
    url = (
        f"https://dialogs.yandex.net/api/v1/skills/{settings.skills_id}/callback/discovery"
    )
    result["ts"] = time.time()
    headers = {
        "Authorization": settings.oauth_token,
        "Content-Type": "application/json",
    }
    requests.post(url, headers=headers, data=json.dumps(result))

async def get_user(token)->DBUser:
    global user_uuid
    async with session_factory() as session:
        query = select(DBUser).filter_by(token=token)
        result = await session.execute(query)
        user = result.scalars().first()
        if user is not None:
            user_uuid=user.uuid
            return user
        return None


def get_token(request: Request):
    auth = request.headers.get("Authorization")
    if not auth:
        raise HTTPException(status_code=400, detail="No Authorization header")

    parts = auth.split(" ", 2)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    else:
        raise HTTPException(status_code=400, detail=f"Invalid token: {auth}")


def random_string(stringLength=8):
    chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for i in range(stringLength))


@app.get("/register/")
async def getRegister(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


@app.post("/register/")
async def postRegister(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    psw: str = Form(...),
    psw2: str = Form(...),
):
    if len(name) > 2 and len(email) > 2 and len(psw) > 2 and psw == psw2:
        hash = pwd_context.hash(psw)
        
        async with session_factory() as session:
            query = select(DBUser).filter_by(email=email)
            result = await session.execute(query)
            result = result.scalars().first()
            if result is not None:
                raise HTTPException(status_code=400, detail="Username already registered")

        async with session_factory() as session:
            stmt = insert(DBUser).values(email=email, name=name, password=hash)
            await session.execute(stmt)
            await session.commit()
        return templates.TemplateResponse(
            "index.html", {"request": request, "name": name}
        )
    else:
        raise HTTPException(status_code=400, detail="error")


@app.get("/")
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "name": "Working"})


@app.post("/v1.0")
async def postv1():
    return "OK"


@app.get("/v1.0")
async def getv1():
    return "OK"


@app.get("/yandex/auth")
async def getАuth(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/yandex/auth")
async def postAuth(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    client_id: str,
    response_type: str,
    redirect_uri: str,
    state: str,
):
    user=None
    if client_id != None and state != None:
        logger.info(form_data.client_id)
        if client_id != settings.client_id:
            raise access_deny()
    if form_data.username != None and form_data.password != None:
        async with session_factory() as session:
            query = select(DBUser).filter_by(email=form_data.username)
            result = await session.execute(query)
            user = result.scalars().first()
            
        if user and pwd_context.verify(form_data.password, user.password):
            global last_code, last_code_user, last_code_time
            last_code = random_string(8)
            last_code_user = form_data.username
            last_code_time = time.time()
            redirect = f"{state}/?code={last_code}"
            return RedirectResponse(redirect, 302)
        else:
            raise access_deny()
    else:
        raise access_deny()


@app.post("/token/")
async def auth_token(request_model=Depends(GetTokenModel)):
    global last_code, last_code_user, last_code_time
    if request_model.client_id != settings.client_id:
        raise access_deny()
    if request_model.code != last_code:
        raise access_deny()
    if request_model.client_secret != settings.client_secret:
        raise access_deny()
    if time.time() - last_code_time > 10:
        raise access_deny()
    access_token = random_string(32)
    async with session_factory() as session:
        query = select(DBUser).filter(DBUser.email == last_code_user)
        result = await session.execute(query)
        user = result.scalars().first()
        if user:
            user.token = access_token
            await session.commit()
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/v1.0/user/unlink")
async def unlink(request: Request):
    access_token = get_token(request)
    request_id = request.headers["x-request-id"]
    async with session_factory() as session:
        query = select(DBUser).filter(DBUser.token == access_token)
        result = await session.execute(query)
        user = result.scalars().first()
        if user:
            user.token = None
            await session.commit()
    return JSONResponse(content={"request_id": request_id})


@app.get("/v1.0/user/devices")
async def get_devices_list(request: Request):
    print("Пришел запрос на список устройств")
    try:
        access_token = get_token(request)
        if access_token == None:
            raise access_deny()
        request_id = request.headers["x-request-id"]
        logger.info(request_id)
        user = await get_user(access_token)
        result = {
            "request_id": request_id,
            "payload": {"user_id": user.uuid, "devices": devices_list},
        }
        return JSONResponse(content=result)
    except Exception as ex:
        return f"Error {type(ex).__name__}: {str(ex)}", 500


# Метод запроса текущего состояния устройства
@app.post("/v1.0/user/devices/query")
async def query(request: Request):
    try:
        # print("Пришел запрос на текущего состояния устройства \n")
        access_token = get_token(request)
        if access_token == None:
            raise access_deny()
        request_id = request.headers["x-request-id"]
        user = await get_user(access_token)
        r = await request.json()
        devices_request = r["devices"]
        result = {
            "request_id": request_id,
            "payload": {"user_id": user.uuid, "devices": []},
        }
        # Для каждого запрошенного устройства...
        for device in devices_request:
            # Убедитесь, что пользователь может получить доступ к этому устройству
            for i in range(0, len(devices_list)):
                if devices_list[i]["id"] == device["id"]:
                    new_device = {
                        "id": device["id"],
                        "capabilities": [],
                        "properties": [],
                    }
                    # Загружаем конфиг устройства
                    new_device["capabilities"] = devices_list[i]["capabilities"]
                    new_device["properties"] = devices_list[i]["properties"]
        result["payload"]["devices"].append(new_device)
        return JSONResponse(content=result)
    except Exception as ex:
        return f"Error {type(ex).__name__}: {str(ex)}", 500


@app.post("/v1.0/user/devices/action")
async def action(request: Request):
    try:
        access_token = get_token(request)
        if access_token == None:
            raise access_deny()
        request_id = request.headers["x-request-id"]
        user = await get_user(access_token)
        r = await request.json()
        devices_request = r["payload"]["devices"]
        result = {"request_id": request_id, "payload": {"devices": []}}
        # Для каждого запрошенного устройства...
        for device in devices_request:
            payload = device["capabilities"]
            payload = json.dumps(payload)
            client.publish("$me/device/commands/" + device["id"], payload)
            time.sleep(0.1)
            new_device = {"id": device["id"], "capabilities": []}
            new_device["capabilities"].append(еvent_list[0])
            new_device["capabilities"][0]["state"]["action_result"] = {"status": "DONE"}
            еvent_list.clear()
            result["payload"]["devices"].append(new_device)
        return JSONResponse(content=result)
    except Exception as ex:
        return f"Error {type(ex).__name__}: {str(ex)}", 500

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
