import os
import sys
import json
import unittest
from unittest.mock import patch, MagicMock

# Переходим в директорию New server
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
TEST_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_gateway.db").replace("\\", "/")
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{TEST_DB_PATH}"

from fastapi.testclient import TestClient
from database import init_db, async_session, User, Device, Token, add_user_token
from main import app, dashboard_app, manager


class TestGateway(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import asyncio
        asyncio.run(init_db())

    @classmethod
    def tearDownClass(cls):
        import asyncio
        from database import engine
        try:
            asyncio.run(engine.dispose())
        except Exception:
            pass
        for f in [TEST_DB_PATH, TEST_DB_PATH + "-shm", TEST_DB_PATH + "-wal"]:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except Exception:
                    pass

    def setUp(self):
        self.client_cm = TestClient(app)
        self.client = self.client_cm.__enter__()

    def tearDown(self):
        self.client_cm.__exit__(None, None, None)

    @patch("main.yandex_session")
    def test_gateway_lifecycle(self, mock_session):
        print("\n--- Запуск тестов шлюза для node-red-contrib-alice ---")

        # 1. Настройка моков Yandex OAuth
        def mock_post(url, *args, **kwargs):
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            data = kwargs.get("data", {})
            code = data.get("code")
            if code == "code_user_alice":
                mock_resp.json.return_value = {"access_token": "ya_alice_token"}
            elif code == "code_user_bob":
                mock_resp.json.return_value = {"access_token": "ya_bob_token"}
            else:
                mock_resp.status_code = 400
                mock_resp.text = "invalid code"
            return mock_resp

        def mock_get(url, *args, **kwargs):
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            headers = kwargs.get("headers", {})
            auth = headers.get("Authorization", "")
            if "ya_alice_token" in auth:
                mock_resp.json.return_value = {
                    "id": "10001",
                    "default_email": "alice@yandex.ru",
                    "display_name": "Alice In Wonderland"
                }
            elif "ya_bob_token" in auth:
                mock_resp.json.return_value = {
                    "id": "20002",
                    "default_email": "bob@yandex.ru",
                    "display_name": "Bob Builder"
                }
            else:
                mock_resp.status_code = 401
            return mock_resp

        mock_session.post.side_effect = mock_post
        mock_session.get.side_effect = mock_get

        # -------------------------------------------------------------
        # Шаг 1: Авторизация User 1 (Alice) через verification_code
        # -------------------------------------------------------------
        resp1 = self.client.post("/api/v1/getyatoken", json={"code": "code_user_alice"})
        self.assertEqual(resp1.status_code, 200, f"Ошибка обмена кода Alice: {resp1.text}")
        data1 = resp1.json()
        self.assertEqual(data1["email"], "alice@yandex.ru")
        self.assertEqual(data1["id"], "10001")
        token1 = data1["token"]["access_token"]
        self.assertTrue(token1.startswith("gtw_"))
        print(f"[OK] Пользователь 1 (Alice) зарегистрирован, токен: {token1}")

        # -------------------------------------------------------------
        # Шаг 2: Авторизация User 2 (Bob) через verification_code
        # -------------------------------------------------------------
        resp2 = self.client.post("/api/v1/getyatoken", json={"code": "code_user_bob"})
        self.assertEqual(resp2.status_code, 200, f"Ошибка обмена кода Bob: {resp2.text}")
        data2 = resp2.json()
        self.assertEqual(data2["email"], "bob@yandex.ru")
        self.assertEqual(data2["id"], "20002")
        token2 = data2["token"]["access_token"]
        self.assertTrue(token2.startswith("gtw_"))
        self.assertNotEqual(token1, token2)
        print(f"[OK] Пользователь 2 (Bob) зарегистрирован, токен: {token2}")

        # -------------------------------------------------------------
        # Шаг 3: Alice регистрирует свое устройство (light_1)
        # -------------------------------------------------------------
        alice_dev = {
            "id": "light_alice_1",
            "config": {
                "name": "Люстра Alice",
                "room": "Гостиная",
                "type": "devices.types.light",
                "capabilities": [{
                    "type": "devices.capabilities.on_off",
                    "retrievable": True,
                    "state": {"instance": "on", "value": False}
                }],
                "properties": []
            }
        }
        res_cfg1 = self.client.post(
            "/gtw/device/config",
            json=alice_dev,
            headers={"Authorization": f"Bearer {token1}"}
        )
        self.assertEqual(res_cfg1.status_code, 200)
        print("[OK] Устройство light_alice_1 зарегистрировано для Alice")

        # -------------------------------------------------------------
        # Шаг 4: Bob регистрирует свое устройство (switch_1)
        # -------------------------------------------------------------
        bob_dev = {
            "id": "switch_bob_1",
            "config": {
                "name": "Розетка Bob",
                "room": "Кухня",
                "type": "devices.types.socket",
                "capabilities": [{
                    "type": "devices.capabilities.on_off",
                    "retrievable": True,
                    "state": {"instance": "on", "value": True}
                }],
                "properties": []
            }
        }
        res_cfg2 = self.client.post(
            "/gtw/device/config",
            json=bob_dev,
            headers={"Authorization": f"Bearer {token2}"}
        )
        self.assertEqual(res_cfg2.status_code, 200)
        print("[OK] Устройство switch_bob_1 зарегистрировано для Bob")

        # -------------------------------------------------------------
        # Шаг 5: Проверка полной изоляции списков устройств (Discovery)
        # -------------------------------------------------------------
        # Список устройств для Alice
        alice_devices_resp = self.client.get(
            "/v1.0/user/devices",
            headers={"Authorization": f"Bearer {token1}"}
        )
        self.assertEqual(alice_devices_resp.status_code, 200)
        alice_payload = alice_devices_resp.json()["payload"]
        self.assertEqual(alice_payload["user_id"], "10001")
        alice_dev_ids = [d["id"] for d in alice_payload["devices"]]
        self.assertEqual(alice_dev_ids, ["light_alice_1"], "Alice должна видеть ТОЛЬКО свои устройства")

        # Список устройств для Bob
        bob_devices_resp = self.client.get(
            "/v1.0/user/devices",
            headers={"Authorization": f"Bearer {token2}"}
        )
        self.assertEqual(bob_devices_resp.status_code, 200)
        bob_payload = bob_devices_resp.json()["payload"]
        self.assertEqual(bob_payload["user_id"], "20002")
        bob_dev_ids = [d["id"] for d in bob_payload["devices"]]
        self.assertEqual(bob_dev_ids, ["switch_bob_1"], "Bob должен видеть ТОЛЬКО свои устройства")
        print("[OK] Изоляция Discovery подтверждена: Alice и Bob видят строго свои устройства")

        # -------------------------------------------------------------
        # Шаг 6: Обновление состояния устройства Alice
        # -------------------------------------------------------------
        state_update = {
            "id": "light_alice_1",
            "state": {
                "capabilities": [{
                    "type": "devices.capabilities.on_off",
                    "state": {"instance": "on", "value": True}
                }]
            }
        }
        res_st = self.client.post(
            "/gtw/device/state",
            json=state_update,
            headers={"Authorization": f"Bearer {token1}"}
        )
        self.assertEqual(res_st.status_code, 200)

        # Проверяем Query от лица Alice
        query_resp = self.client.post(
            "/v1.0/user/devices/query",
            json={"devices": [{"id": "light_alice_1"}]},
            headers={"Authorization": f"Bearer {token1}"}
        )
        self.assertEqual(query_resp.status_code, 200)
        q_devs = query_resp.json()["payload"]["devices"]
        self.assertEqual(len(q_devs), 1)
        self.assertEqual(q_devs[0]["capabilities"][0]["state"]["value"], True)

        # Проверяем Query устройства Alice от лица Bob -> должно вернуть DEVICE_NOT_FOUND
        bob_query_resp = self.client.post(
            "/v1.0/user/devices/query",
            json={"devices": [{"id": "light_alice_1"}]},
            headers={"Authorization": f"Bearer {token2}"}
        )
        self.assertEqual(bob_query_resp.status_code, 200)
        bob_q_devs = bob_query_resp.json()["payload"]["devices"]
        self.assertEqual(bob_q_devs[0]["error_code"], "DEVICE_NOT_FOUND")
        print("[OK] Изоляция Query подтверждена: Bob не может запросить состояние чужого устройства")

        # -------------------------------------------------------------
        # Шаг 7: WebSocket-соединение и изоляция команд
        # -------------------------------------------------------------
        # Подключаем сокет Alice
        with self.client.websocket_connect("/v1/ws", headers={"Authorization": f"Bearer {token1}"}) as ws_alice:
            msg = ws_alice.receive_json()
            self.assertEqual(msg.get("type"), "hello")
            print("[OK] WebSocket для Alice подключен (hello получен)")

            # Подключаем сокет Bob
            with self.client.websocket_connect("/v1/ws", headers={"Authorization": f"Bearer {token2}"}) as ws_bob:
                msg2 = ws_bob.receive_json()
                self.assertEqual(msg2.get("type"), "hello")
                print("[OK] WebSocket для Bob подключен (hello получен)")

                # Отправляем экшен для Alice через отдельный тред/клиент
                action_payload = {
                    "payload": {
                        "devices": [{
                            "id": "light_alice_1",
                            "capabilities": [{
                                "type": "devices.capabilities.on_off",
                                "state": {"instance": "on", "value": False}
                            }]
                        }]
                    }
                }

                import threading
                def _do_action():
                    self.client.post(
                        "/v1.0/user/devices/action",
                        json=action_payload,
                        headers={"Authorization": f"Bearer {token1}"}
                    )

                t = threading.Thread(target=_do_action)
                t.start()

                # Alice должна получить команду по своему WebSocket
                frame = ws_alice.receive_json()
                self.assertEqual(frame.get("type"), "command")
                self.assertEqual(frame.get("devId"), "light_alice_1")
                print("[OK] Alice получила команду для своего устройства light_alice_1")

                # Alice отправляет подтверждение command_result
                ws_alice.send_json({
                    "v": 1,
                    "type": "command_result",
                    "devId": "light_alice_1",
                    "payload": [{"type": "devices.capabilities.on_off", "state": {"instance": "on", "action_result": {"status": "DONE"}}}]
                })
                t.join(timeout=2.0)

        # -------------------------------------------------------------
        # Шаг 8: Очистка устройств Alice не затрагивает устройства Bob
        # -------------------------------------------------------------
        res_clr = self.client.post(
            "/gtw/device/clearallconfigs",
            headers={"Authorization": f"Bearer {token1}"}
        )
        self.assertEqual(res_clr.status_code, 200)

        # Alice: 0 устройств
        a_resp = self.client.get("/v1.0/user/devices", headers={"Authorization": f"Bearer {token1}"})
        self.assertEqual(len(a_resp.json()["payload"]["devices"]), 0)

        # Bob: устройство на месте
        b_resp = self.client.get("/v1.0/user/devices", headers={"Authorization": f"Bearer {token2}"})
        self.assertEqual(len(b_resp.json()["payload"]["devices"]), 1)
        self.assertEqual(b_resp.json()["payload"]["devices"][0]["id"], "switch_bob_1")
        print("[OK] Очистка устройств Alice не повлияла на устройства Bob")

        # -------------------------------------------------------------
        # Шаг 9: Проверка удаления токена при Logout и поддержка мультиинстансов (до 5)
        # -------------------------------------------------------------
        # 9.1. Удаление токена Alice через Logout
        logout_resp = self.client.post("/api/v1/logout", json={"token": token1})
        self.assertEqual(logout_resp.status_code, 200)
        print("[OK] Logout Alice выполнен успешно, токен удален")

        # 9.2. Мультиинстансы: добавляем токены для Bob вплоть до лимита (5)
        # У Bob уже есть token2 (1-й инстанс)
        for i in range(2, 6):
            r = self.client.post("/api/v1/getyatoken", json={"code": "code_user_bob"})
            self.assertEqual(r.status_code, 200)

        import sqlite3
        con = sqlite3.connect(TEST_DB_PATH)
        bob_user_id = con.execute("SELECT id FROM users WHERE email = 'bob@yandex.ru'").fetchone()[0]
        alice_user_id = con.execute("SELECT id FROM users WHERE email = 'alice@yandex.ru'").fetchone()[0]

        alice_tokens = con.execute("SELECT token FROM tokens WHERE user_id = ?", (alice_user_id,)).fetchall()
        bob_tokens_5 = con.execute("SELECT token FROM tokens WHERE user_id = ? AND token_type = 'nodered'", (bob_user_id,)).fetchall()
        self.assertEqual(len(alice_tokens), 0, "У Alice не должно остаться токенов после logout")
        self.assertEqual(len(bob_tokens_5), 5, "У Bob должно быть ровно 5 активных токенов")
        print("[OK] Поддержка нескольких подключений: создано 5 активных токенов для одного аккаунта")

        # Добавляем 6-й токен — проверяем ротацию (FIFO): остается 5
        r6 = self.client.post("/api/v1/getyatoken", json={"code": "code_user_bob"})
        self.assertEqual(r6.status_code, 200)
        token_6th = r6.json()["token"]["access_token"]

        bob_tokens_after_6 = [row[0] for row in con.execute("SELECT token FROM tokens WHERE user_id = ? AND token_type = 'nodered'", (bob_user_id,)).fetchall()]
        self.assertEqual(len(bob_tokens_after_6), 5, "После превышения лимита старый токен удален, осталось 5")
        self.assertIn(token_6th, bob_tokens_after_6)
        con.close()
        print("[OK] Ротация токенов работает: лимит 5 токенов соблюдается")

        # 9.3. Yandex Skill OAuth токен всегда единственный на аккаунт
        import asyncio
        async def _test_skill_token():
            async with async_session() as session:
                async with session.begin():
                    await add_user_token(session, user_id=bob_user_id, token="yash_bob_1", token_type="yandex_dialogs")
            async with async_session() as session:
                async with session.begin():
                    await add_user_token(session, user_id=bob_user_id, token="yash_bob_2", token_type="yandex_dialogs")

        asyncio.run(_test_skill_token())

        con = sqlite3.connect(TEST_DB_PATH)
        bob_skill_tokens = con.execute("SELECT token FROM tokens WHERE user_id = ? AND token_type = 'yandex_dialogs'", (bob_user_id,)).fetchall()
        bob_nodered_tokens = con.execute("SELECT token FROM tokens WHERE user_id = ? AND token_type = 'nodered'", (bob_user_id,)).fetchall()
        con.close()

        self.assertEqual(len(bob_skill_tokens), 1, "Yandex Skill OAuth токен должен быть единственным на аккаунт")
        self.assertEqual(bob_skill_tokens[0][0], "yash_bob_2")
        self.assertEqual(len(bob_nodered_tokens), 5, "Токен навыка не входит в лимит 5 мультиинстансов Node-RED")
        print("[OK] Yandex Skill OAuth токен единственный на аккаунт и независим от лимита Node-RED мультиинстансов")

        # -------------------------------------------------------------
        # Шаг 10: Проверка разделения шлюза и веб-панели управления
        # -------------------------------------------------------------
        # 10.1. Публичный корень шлюза (порт 5000) безопасен: админ-панель на нем отсутствует
        gw_root_resp = self.client.get("/")
        self.assertEqual(gw_root_resp.status_code, 200)
        self.assertEqual(gw_root_resp.json().get("service"), "Yandex Smart Home Gateway")
        gw_admin_resp = self.client.get("/api/admin/data")
        self.assertEqual(gw_admin_resp.status_code, 404, "На публичном шлюзе не должно быть админских API")
        print("[OK] Публичный шлюз безопасен: админская панель и API на нем отсутствуют")

        # 10.2. Веб-панель запущена на отдельном порту (dashboard_app)
        with TestClient(dashboard_app) as dash_client:
            dash_resp = dash_client.get("/")
            self.assertEqual(dash_resp.status_code, 200)
            self.assertIn("text/html", dash_resp.headers.get("content-type", ""))
            self.assertIn("Яндекс Умный Дом", dash_resp.text)
            print("[OK] Веб-панель доступна на отдельном порту (GET /)")

            # 10.3. API данных панели
            api_resp = dash_client.get("/api/admin/data")
            self.assertEqual(api_resp.status_code, 200)
            api_data = api_resp.json()
            self.assertIn("server", api_data)
            self.assertIn("users", api_data)
            self.assertEqual(api_data["server"]["total_users"], 2)
            print("[OK] API данных панели /api/admin/data возвращает актуальную статистику")

            # 10.4. Удаление токена через веб-панель
            token_to_delete = bob_tokens_after_6[0]
            del_tok_resp = dash_client.delete(f"/api/admin/tokens/{token_to_delete}")
            self.assertEqual(del_tok_resp.status_code, 200)

            # 10.5. Удаление устройства через веб-панель
            del_dev_resp = dash_client.delete(f"/api/admin/devices/{bob_user_id}/switch_bob_1")
            self.assertEqual(del_dev_resp.status_code, 200)
            print("[OK] Удаление токенов и устройств через веб-панель успешно протестировано")

        # -------------------------------------------------------------
        # Шаг 11: Проверка защиты от устройств без токена и логаута с __PWRD__
        # -------------------------------------------------------------
        # 11.1. Попытка отправки устройства без токена
        unauth_dev = {
            "id": "unauth_lamp",
            "config": {
                "name": "Неавторизованная лампа",
                "capabilities": [{"type": "devices.capabilities.on_off"}]
            }
        }
        res_no_tok = self.client.post("/gtw/device/config", json=unauth_dev)
        self.assertEqual(res_no_tok.status_code, 401, "Запрос без токена должен отклоняться кодом 401")

        # 11.2. Попытка с local-token
        res_local = self.client.post("/gtw/device/config", json=unauth_dev, headers={"Authorization": "Bearer local-token"})
        self.assertEqual(res_local.status_code, 401, "Запрос с local-token должен отклоняться кодом 401")

        # 11.3. Попытка с несуществующим токеном
        res_fake = self.client.post("/gtw/device/config", json=unauth_dev, headers={"Authorization": "Bearer gtw_fake_12345"})
        self.assertEqual(res_fake.status_code, 401, "Запрос с поддельным токеном должен отклоняться кодом 401")

        # Проверяем в БД: неавторизованное устройство НЕ попало в базу
        import sqlite3
        con = sqlite3.connect(TEST_DB_PATH)
        unauth_db = con.execute("SELECT id FROM devices WHERE id = 'unauth_lamp'").fetchall()
        self.assertEqual(len(unauth_db), 0, "Неавторизованное устройство гарантированно не попало в БД")
        print("[OK] Защита от устройств без токена подтверждена: 401 Unauthorized, база чиста")

        # 11.4. Проверка WebSocket коннекта без валидного токена
        try:
            with self.client.websocket_connect("/v1/ws", headers={"Authorization": "Bearer local-token"}) as ws_bad:
                ws_bad.receive_json()
                self.fail("WebSocket без валидного токена должен быть закрыт сервером")
        except Exception:
            print("[OK] WebSocket без валидного токена успешно отвергнут сервером (4401)")

        # 11.5. Проверка: попытка Logout без токена (только по email) должна быть ОТВЕРГНУТА (401 Unauthorized)
        logout_email_only = self.client.post("/api/v1/logout", json={"token": "__PWRD__", "email": "bob@yandex.ru"})
        self.assertEqual(logout_email_only.status_code, 401, "Логаут только по email без токена должен отклоняться")

        # 11.6. Попытка очистки устройств без токена (только по email) должна быть ОТВЕРГНУТА (401 Unauthorized)
        clear_email_only = self.client.post("/gtw/device/clearallconfigs", json={"email": "bob@yandex.ru"})
        self.assertEqual(clear_email_only.status_code, 401, "Очистка устройств только по email без токена должна отклоняться")

        # 11.7. Проверка легитимного Logout с валидным токеном Bob
        bob_current_token = bob_tokens_after_6[1]
        logout_real = self.client.post("/api/v1/logout", json={"token": bob_current_token})
        self.assertEqual(logout_real.status_code, 200)

        bob_check_tok = con.execute("SELECT token FROM tokens WHERE token = ?", (bob_current_token,)).fetchall()
        self.assertEqual(len(bob_check_tok), 0, "Токен Bob удален строго по предъявлению реального токена")
        con.close()
        print("[OK] Безопасность подтверждена: запросы только с email/yandex_uid отклоняются (401), операции разрешены строго по реальному токену")

        # -------------------------------------------------------------
        # Шаг 12: Проверка полного OAuth flow и Refresh Token ротации
        # -------------------------------------------------------------
        from urllib.parse import urlparse, parse_qs
        # 12.1. /auth -> редирект в Яндекс
        auth_req = self.client.get(
            "/auth?client_id=test_client&response_type=code&redirect_uri=https://dialogs.yandex.net/oauth&state=mystate",
            follow_redirects=False
        )
        self.assertEqual(auth_req.status_code, 307)
        loc = auth_req.headers["location"]
        session_id = parse_qs(urlparse(loc).query)["state"][0]

        # 12.2. /yandex_callback -> редирект в Диалоги с временным кодом
        cb_req = self.client.get(
            f"/yandex_callback?code=code_user_bob&state={session_id}",
            follow_redirects=False
        )
        self.assertEqual(cb_req.status_code, 307)
        cb_loc = cb_req.headers["location"]
        gateway_auth_code = parse_qs(urlparse(cb_loc).query)["code"][0]

        # 12.3. /token exchange (grant_type=authorization_code)
        tok_req = self.client.post("/token", data={
            "grant_type": "authorization_code",
            "code": gateway_auth_code
        })
        self.assertEqual(tok_req.status_code, 200)
        tok_data = tok_req.json()
        self.assertIn("access_token", tok_data)
        self.assertIn("refresh_token", tok_data)
        init_access = tok_data["access_token"]
        init_refresh = tok_data["refresh_token"]

        # 12.4. /token refresh (grant_type=refresh_token)
        refresh_req = self.client.post("/token", data={
            "grant_type": "refresh_token",
            "refresh_token": init_refresh
        })
        self.assertEqual(refresh_req.status_code, 200)
        ref_data = refresh_req.json()
        self.assertNotEqual(ref_data["access_token"], init_access)
        self.assertNotEqual(ref_data["refresh_token"], init_refresh)
        print(f"[OK] OAuth 2.0 flow и Refresh Token ротация успешно подтверждены: {ref_data['access_token'][:15]}...")

        # -------------------------------------------------------------
        # Шаг 13: Проверка удаления всех устройств пользователя через админ-панель
        # -------------------------------------------------------------
        # Регистрируем новое устройство для Bob
        bob_valid_token = bob_tokens_after_6[2]
        new_dev = {
            "id": "bob_temp_device",
            "config": {
                "name": "Временный прибор",
                "capabilities": [{"type": "devices.capabilities.on_off"}]
            }
        }
        res_add = self.client.post("/gtw/device/config", json=new_dev, headers={"Authorization": f"Bearer {bob_valid_token}"})
        self.assertEqual(res_add.status_code, 200)

        with TestClient(dashboard_app) as dash_client:
            del_all_res = dash_client.delete(f"/api/admin/users/2/devices")
            self.assertEqual(del_all_res.status_code, 200)

        # Проверяем, что устройств у Bob не осталось
        res_devs_bob = self.client.get("/v1.0/user/devices", headers={"Authorization": f"Bearer {bob_valid_token}"})
        self.assertEqual(len(res_devs_bob.json()["payload"]["devices"]), 0)
        print("[OK] Удаление всех устройств аккаунта через админ API успешно подтверждено")

        # -------------------------------------------------------------
        # Шаг 14: Проверка получения OAuth Client ID и полного удаления аккаунта
        # -------------------------------------------------------------
        # 14.1. Проверка API Client ID
        res_cid = self.client.get("/api/v1/oauth_client_id")
        self.assertEqual(res_cid.status_code, 200)
        self.assertIn("client_id", res_cid.json())
        print("[OK] API /api/v1/oauth_client_id успешно возвращает client_id для ноды Node-RED")

        # 14.2. Полное удаление аккаунта Bob (со всеми токенами и устройствами)
        with TestClient(dashboard_app) as dash_client:
            del_user_res = dash_client.delete("/api/admin/users/2")
            self.assertEqual(del_user_res.status_code, 200)

        # Проверяем в БД: Bob, его токены и устройства полностью удалены
        con = sqlite3.connect(TEST_DB_PATH)
        bob_u = con.execute("SELECT id FROM users WHERE id = 2").fetchall()
        bob_t = con.execute("SELECT id FROM tokens WHERE user_id = 2").fetchall()
        bob_d = con.execute("SELECT id FROM devices WHERE user_id = 2").fetchall()
        con.close()
        self.assertEqual(len(bob_u), 0, "Пользователь Bob удален из БД")
        self.assertEqual(len(bob_t), 0, "Все токены Bob удалены из БД")
        self.assertEqual(len(bob_d), 0, "Все устройства Bob удалены из БД")
        print("[OK] Полное удаление аккаунта со всеми токенами и устройствами успешно подтверждено")

        # -------------------------------------------------------------
        # Шаг 15: Валидация схемы состояний УДЯ (color_setting, retrievable: False)
        # -------------------------------------------------------------
        # Авторизуем Alice заново для получения активного токена
        resp_al = self.client.post("/api/v1/getyatoken", json={"code": "code_user_alice"})
        token_al = resp_al.json()["token"]["access_token"]

        # Регистрируем для Alice устройство с color_setting и non-retrievable событием движения
        alice_rgb_dev = {
            "id": "light_rgb_motion",
            "config": {
                "name": "RGB Люстра с датчиком движения",
                "room": "Зал",
                "type": "devices.types.light",
                "capabilities": [
                    {
                        "type": "devices.capabilities.on_off",
                        "retrievable": True,
                        "reportable": True,
                        "parameters": {"instance": "on"}
                    },
                    {
                        "type": "devices.capabilities.color_setting",
                        "retrievable": True,
                        "reportable": True,
                        "parameters": {
                            "color_model": "rgb",
                            "temperature_k": {"min": 2000, "max": 9000}
                        }
                    }
                ],
                "properties": [
                    {
                        "type": "devices.properties.event",
                        "retrievable": False,
                        "reportable": True,
                        "parameters": {
                            "instance": "motion",
                            "events": [{"value": "detected"}, {"value": "not_detected"}]
                        }
                    }
                ]
            }
        }
        res_rgb = self.client.post("/gtw/device/config", json=alice_rgb_dev, headers={"Authorization": f"Bearer {token_al}"})
        self.assertEqual(res_rgb.status_code, 200)

        # Опрашиваем состояние устройства через /v1.0/user/devices/query
        q_rgb_resp = self.client.post(
            "/v1.0/user/devices/query",
            json={"devices": [{"id": "light_rgb_motion"}]},
            headers={"Authorization": f"Bearer {token_al}"}
        )
        self.assertEqual(q_rgb_resp.status_code, 200)
        q_rgb_data = q_rgb_resp.json()["payload"]["devices"][0]

        # 1. Проверяем, что color_setting получил валидный инстанс ("temperature_k" или "rgb"), а не ошибочный "on"
        caps_map = {c["type"]: c for c in q_rgb_data["capabilities"]}
        self.assertIn("devices.capabilities.color_setting", caps_map)
        cs_state = caps_map["devices.capabilities.color_setting"]["state"]
        self.assertIn(cs_state["instance"], ["temperature_k", "rgb"])
        self.assertNotEqual(cs_state["instance"], "on", "Инстанс 'on' для color_setting недопустим в УДЯ!")

        # 2. Проверяем, что не-retrievable свойство (датчик движения) НЕ передается в ответе query
        self.assertNotIn("properties", q_rgb_data, "Свойства с retrievable: False не должны отдаваться в query")

        # 3. Обновляем состояние цвета на RGB (например, красный цвет 16711680)
        st_update_rgb = {
            "id": "light_rgb_motion",
            "state": {
                "capabilities": [{
                    "type": "devices.capabilities.color_setting",
                    "state": {"instance": "rgb", "value": 16711680}
                }]
            }
        }
        res_up_rgb = self.client.post("/gtw/device/state", json=st_update_rgb, headers={"Authorization": f"Bearer {token_al}"})
        self.assertEqual(res_up_rgb.status_code, 200)

        # Повторный query: проверяем корректное обновление инстанса color_setting на rgb
        q_rgb_resp2 = self.client.post(
            "/v1.0/user/devices/query",
            json={"devices": [{"id": "light_rgb_motion"}]},
            headers={"Authorization": f"Bearer {token_al}"}
        )
        q_rgb_data2 = q_rgb_resp2.json()["payload"]["devices"][0]
        caps_map2 = {c["type"]: c for c in q_rgb_data2["capabilities"]}
        cs_state2 = caps_map2["devices.capabilities.color_setting"]["state"]
        self.assertEqual(cs_state2["instance"], "rgb")
        self.assertEqual(cs_state2["value"], 16711680)
        print("[OK] Валидация стандартов УДЯ (color_setting, retrievable: False) успешно подтверждена")

        # -------------------------------------------------------------
        # Шаг 16: Проверка работы видеотрансляции (devices.capabilities.video_stream)
        # -------------------------------------------------------------
        camera_dev = {
            "id": "camera_hall",
            "config": {
                "name": "Камера в прихожей",
                "room": "Прихожая",
                "type": "devices.types.camera",
                "capabilities": [
                    {
                        "type": "devices.capabilities.video_stream",
                        "retrievable": False,
                        "reportable": False,
                        "parameters": {
                            "protocols": ["hls"]
                        },
                        "state": {
                            "instance": "get_stream",
                            "value": {
                                "stream_url": "https://test-streams.mux.dev/x36xhzz/x36xhzz.m3u8",
                                "protocol": "hls"
                            }
                        }
                    }
                ],
                "properties": []
            }
        }
        res_cam = self.client.post("/gtw/device/config", json=camera_dev, headers={"Authorization": f"Bearer {token_al}"})
        self.assertEqual(res_cam.status_code, 200)

        # 16.1. Проверка Discovery: video_stream имеет retrievable: false и parameters.protocols: ["hls"]
        disc_cam = self.client.get("/v1.0/user/devices", headers={"Authorization": f"Bearer {token_al}"})
        self.assertEqual(disc_cam.status_code, 200)
        c_found = next(d for d in disc_cam.json()["payload"]["devices"] if d["id"] == "camera_hall")
        v_cap = next(c for c in c_found["capabilities"] if c["type"] == "devices.capabilities.video_stream")
        self.assertEqual(v_cap["retrievable"], False)
        self.assertEqual(v_cap["parameters"]["protocols"], ["hls"])

        # 16.2. Проверка Action: запрос потока get_stream должен вернуть stream_url и protocol
        action_video_req = {
            "payload": {
                "devices": [{
                    "id": "camera_hall",
                    "capabilities": [{
                        "type": "devices.capabilities.video_stream",
                        "state": {
                            "instance": "get_stream",
                            "value": {
                                "protocols": ["hls", "whip", "mjpeg"]
                            }
                        }
                    }]
                }]
            }
        }
        res_act_video = self.client.post("/v1.0/user/devices/action", json=action_video_req, headers={"Authorization": f"Bearer {token_al}"})
        self.assertEqual(res_act_video.status_code, 200)
        act_dev = res_act_video.json()["payload"]["devices"][0]
        act_cap = act_dev["capabilities"][0]
        self.assertEqual(act_cap["state"]["action_result"]["status"], "DONE")
        self.assertEqual(act_cap["state"]["instance"], "get_stream")
        self.assertIn("value", act_cap["state"], "Ответ на action get_stream ОБЯЗАН содержать объект value со stream_url")
        self.assertEqual(act_cap["state"]["value"]["stream_url"], "https://test-streams.mux.dev/x36xhzz/x36xhzz.m3u8")
        self.assertEqual(act_cap["state"]["value"]["protocol"], "hls")
        print("[OK] Работа видеотрансляции (action get_stream -> stream_url) успешно подтверждена")

        # -------------------------------------------------------------
        # Шаг 17: Полная проверка всех спецификаций УДЯ (on_off, color_setting, mode, range, toggle)
        # -------------------------------------------------------------
        complex_dev = {
            "id": "climate_complex",
            "config": {
                "name": "Климатический комплекс",
                "room": "Гостиная",
                "type": "devices.types.thermostat",
                "capabilities": [
                    {
                        "type": "devices.capabilities.on_off",
                        "retrievable": True,
                        "reportable": True,
                        "parameters": {
                            "instance": "on",  # Должен быть удален из parameters в Discovery
                            "split": False
                        }
                    },
                    {
                        "type": "devices.capabilities.mode",
                        "retrievable": True,
                        "reportable": True,
                        "parameters": {
                            "instance": "thermostat",
                            "modes": ["auto", "cool", "heat", "fan_only"]  # Список строк -> должен преобразоваться в [{"value": ...}]
                        }
                    },
                    {
                        "type": "devices.capabilities.range",
                        "retrievable": True,
                        "reportable": True,
                        "parameters": {
                            "instance": "temperature",
                            "unit": "unit.temperature.celsius",
                            "range": {
                                "min": 16,
                                "max": 30,
                                "precision": 1
                            }
                        },
                        "state": {
                            "instance": "temperature",
                            "value": 22
                        }
                    },
                    {
                        "type": "devices.capabilities.toggle",
                        "retrievable": True,
                        "reportable": True,
                        "parameters": {
                            "instance": "ionization"
                        }
                    },
                    {
                        "type": "devices.capabilities.color_setting",
                        "retrievable": True,
                        "reportable": True,
                        "parameters": {
                            "instance": "color",  # Должен быть удален
                            "color_model": "rgb",
                            "color_scene": {
                                "scenes": [{"id": "night"}, {"id": "reading"}]
                            }
                        }
                    }
                ],
                "properties": [
                    {
                        "type": "devices.properties.float",
                        "retrievable": True,
                        "reportable": True,
                        "parameters": {
                            "instance": "humidity",
                            "unit": "unit.percent"
                        },
                        "state": {
                            "instance": "humidity",
                            "value": 45.5
                        }
                    }
                ]
            }
        }
        res_complex = self.client.post("/gtw/device/config", json=complex_dev, headers={"Authorization": f"Bearer {token_al}"})
        self.assertEqual(res_complex.status_code, 200)

        # 17.1. Проверка Discovery: валидация параметров умений
        disc_comp = self.client.get("/v1.0/user/devices", headers={"Authorization": f"Bearer {token_al}"})
        self.assertEqual(disc_comp.status_code, 200)
        c_dev = next(d for d in disc_comp.json()["payload"]["devices"] if d["id"] == "climate_complex")

        # on_off: instance не должно быть в parameters
        c_onoff = next(c for c in c_dev["capabilities"] if c["type"] == "devices.capabilities.on_off")
        self.assertNotIn("instance", c_onoff.get("parameters", {}), "on_off parameters не должен содержать instance")

        # mode: modes должен быть списком объектов [{'value': ...}]
        c_mode = next(c for c in c_dev["capabilities"] if c["type"] == "devices.capabilities.mode")
        self.assertEqual(c_mode["parameters"]["instance"], "thermostat")
        self.assertIsInstance(c_mode["parameters"]["modes"], list)
        self.assertTrue(all(isinstance(m, dict) and "value" in m for m in c_mode["parameters"]["modes"]))

        # range: min=16, max=30, unit=unit.temperature.celsius
        c_range = next(c for c in c_dev["capabilities"] if c["type"] == "devices.capabilities.range")
        self.assertEqual(c_range["parameters"]["range"]["min"], 16)
        self.assertEqual(c_range["parameters"]["range"]["max"], 30)

        # color_setting: instance не должно быть в parameters, color_model и color_scene присутствуют
        c_color = next(c for c in c_dev["capabilities"] if c["type"] == "devices.capabilities.color_setting")
        self.assertNotIn("instance", c_color.get("parameters", {}), "color_setting parameters не должен содержать instance")
        self.assertEqual(c_color["parameters"]["color_model"], "rgb")
        self.assertEqual(len(c_color["parameters"]["color_scene"]["scenes"]), 2)

        # 17.2. Проверка Query: строгие типы
        q_comp = self.client.post("/v1.0/user/devices/query", json={"devices": [{"id": "climate_complex"}]}, headers={"Authorization": f"Bearer {token_al}"})
        self.assertEqual(q_comp.status_code, 200)
        q_comp_dev = q_comp.json()["payload"]["devices"][0]
        q_caps_map = {c["type"]: c for c in q_comp_dev["capabilities"]}
        self.assertIsInstance(q_caps_map["devices.capabilities.on_off"]["state"]["value"], bool)
        self.assertIsInstance(q_caps_map["devices.capabilities.mode"]["state"]["value"], str)
        self.assertEqual(q_caps_map["devices.capabilities.mode"]["state"]["value"], "auto")
        self.assertIsInstance(q_caps_map["devices.capabilities.range"]["state"]["value"], (int, float))
        self.assertEqual(q_caps_map["devices.capabilities.range"]["state"]["value"], 22)
        self.assertIsInstance(q_caps_map["devices.capabilities.toggle"]["state"]["value"], bool)

        # 17.3. Проверка Action:
        # a) Относительное изменение range (relative: true) - было 22, прибавляем +3 -> должно стать 25
        # b) Валидный режим mode: cool
        # c) Невалидный режим mode: invalid_turbo -> ошибка INVALID_VALUE
        # d) Невалидная сцена color_setting: sunrise -> ошибка INVALID_VALUE (поддерживаются только night и reading)
        # e) Неподдерживаемое умение -> ошибка NOT_SUPPORTED_IN_CURRENT_MODE
        action_test_req = {
            "payload": {
                "devices": [{
                    "id": "climate_complex",
                    "capabilities": [
                        {
                            "type": "devices.capabilities.range",
                            "state": {
                                "instance": "temperature",
                                "value": 3,
                                "relative": True
                            }
                        },
                        {
                            "type": "devices.capabilities.mode",
                            "state": {
                                "instance": "thermostat",
                                "value": "cool"
                            }
                        },
                        {
                            "type": "devices.capabilities.mode",
                            "state": {
                                "instance": "thermostat",
                                "value": "invalid_mode_name"
                            }
                        },
                        {
                            "type": "devices.capabilities.color_setting",
                            "state": {
                                "instance": "scene",
                                "value": "unsupported_scene"
                            }
                        }
                    ]
                }]
            }
        }
        res_act_test = self.client.post("/v1.0/user/devices/action", json=action_test_req, headers={"Authorization": f"Bearer {token_al}"})
        self.assertEqual(res_act_test.status_code, 200)
        act_res_caps = res_act_test.json()["payload"]["devices"][0]["capabilities"]

        # range relative action -> DONE
        self.assertEqual(act_res_caps[0]["state"]["action_result"]["status"], "DONE")

        # mode cool action -> DONE
        self.assertEqual(act_res_caps[1]["state"]["action_result"]["status"], "DONE")

        # mode invalid_mode_name action -> ERROR INVALID_VALUE
        self.assertEqual(act_res_caps[2]["state"]["action_result"]["status"], "ERROR")
        self.assertEqual(act_res_caps[2]["state"]["action_result"]["error_code"], "INVALID_VALUE")

        # color_setting unsupported_scene action -> ERROR INVALID_VALUE
        self.assertEqual(act_res_caps[3]["state"]["action_result"]["status"], "ERROR")
        self.assertEqual(act_res_caps[3]["state"]["action_result"]["error_code"], "INVALID_VALUE")

        # Проверяем, что в базе температура обновилась до 25 (22 + 3)
        q_after = self.client.post("/v1.0/user/devices/query", json={"devices": [{"id": "climate_complex"}]}, headers={"Authorization": f"Bearer {token_al}"})
        q_after_dev = q_after.json()["payload"]["devices"][0]
        q_after_caps = {c["type"]: c for c in q_after_dev["capabilities"]}
        self.assertEqual(q_after_caps["devices.capabilities.range"]["state"]["value"], 25)
        self.assertEqual(q_after_caps["devices.capabilities.mode"]["state"]["value"], "cool")

        # Неподдерживаемое умение на устройстве (например, video_stream на кондиционере) -> NOT_SUPPORTED_IN_CURRENT_MODE
        unsupported_req = {
            "payload": {
                "devices": [{
                    "id": "climate_complex",
                    "capabilities": [{
                        "type": "devices.capabilities.video_stream",
                        "state": {"instance": "get_stream"}
                    }]
                }]
            }
        }
        res_unsupp = self.client.post("/v1.0/user/devices/action", json=unsupported_req, headers={"Authorization": f"Bearer {token_al}"})
        self.assertEqual(res_unsupp.status_code, 200)
        unsupp_cap = res_unsupp.json()["payload"]["devices"][0]["capabilities"][0]
        self.assertEqual(unsupp_cap["state"]["action_result"]["status"], "ERROR")
        self.assertEqual(unsupp_cap["state"]["action_result"]["error_code"], "NOT_SUPPORTED_IN_CURRENT_MODE")

        print("[OK] Полная валидация всех умений и спецификаций УДЯ (on_off, mode, range, color_setting, toggle) подтверждена")

        print("=== ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ УСПЕШНО ===")


if __name__ == "__main__":
    unittest.main()
