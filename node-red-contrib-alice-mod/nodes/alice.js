"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
const axios_1 = __importDefault(require("axios"));
const ws_1 = __importDefault(require("ws"));
const DEFAULT_WS_URL = process.env.ALICE_WS_URL || "ws://localhost:5000/v1/ws";
const DEFAULT_API_URL = process.env.ALICE_API_URL || process.env.ALICE_SERVER_URL || "http://localhost:5000";
const RECONNECT_MIN_MS = 1000;
const RECONNECT_MAX_MS = 60000;
const RECONNECT_JITTER_MS = 10000;
const WATCHDOG_TIMEOUT_MS = 90000;
const HANDSHAKE_TIMEOUT_MS = 15000;
const CLOSE_FAILSAFE_MS = 1500;
module.exports = (RED) => {
    function AliceService(config) {
        RED.nodes.createNode(this, config);
        this.debug("Starting Alice service... ID: " + this.id);
        const email = (this.credentials && this.credentials.email) || "default-user";
        const rawToken = (this.credentials && this.credentials.token) || "";
        const serverUrl = (config.serverUrl || DEFAULT_API_URL).replace(/\/+$/, '');
        let wsUrl = config.wsUrl || process.env.ALICE_WS_URL || "";
        if (!wsUrl) {
            if (serverUrl.startsWith("https://")) {
                wsUrl = serverUrl.replace(/^https:\/\//, "wss://") + "/v1/ws";
            }
            else if (serverUrl.startsWith("http://")) {
                wsUrl = serverUrl.replace(/^http:\/\//, "ws://") + "/v1/ws";
            }
            else {
                wsUrl = DEFAULT_WS_URL;
            }
        }
        if (wsUrl && !wsUrl.includes("/v1/ws")) {
            wsUrl = wsUrl.replace(/\/+$/, '') + "/v1/ws";
        }
        if (!rawToken || rawToken === "local-token" || rawToken === "__PWRD__") {
            this.error("Требуется авторизация в настройках ноды (отсутствует токен)");
            this.isOnline = false;
            this.getToken = () => "";
            this.getApiUrl = () => serverUrl;
            return;
        }
        let accessToken = "";
        try {
            const parsed = JSON.parse(rawToken);
            accessToken = parsed.access_token || rawToken;
        }
        catch (_err) {
            accessToken = rawToken;
        }
        if (!accessToken || accessToken === "local-token" || accessToken === "__PWRD__") {
            this.error("Недействительный токен авторизации. Требуется повторная авторизация в настройках ноды.");
            this.isOnline = false;
            this.getToken = () => "";
            this.getApiUrl = () => serverUrl;
            return;
        }
        this.getToken = () => accessToken;
        this.getApiUrl = () => serverUrl;
        const suburl = Buffer.from(email).toString('base64');
        const handleClearAll = (_req, res) => {
            if (!accessToken || accessToken === "local-token" || accessToken === "__PWRD__") {
                this.warn("Cannot clear devices: node is not authorized with Yandex ID");
                res.status(401).json({ detail: "Требуется авторизация через Яндекс ID" });
                return;
            }
            this.debug("Sending clearallconfigs to " + serverUrl + " with token " + accessToken.substring(0, 12) + "...");
            axios_1.default.request({
                method: 'POST',
                url: serverUrl + '/gtw/device/clearallconfigs',
                headers: {
                    'content-type': 'application/json',
                    'Authorization': "Bearer " + accessToken
                },
                data: {
                    token: accessToken
                }
            })
                .then(() => {
                this.trace("All devices configs deleted on gateway successfully");
                res.sendStatus(200);
            })
                .catch((error) => {
                var _a, _b;
                this.debug("Error when delete All devices configs deleted on gateway: " + ((error === null || error === void 0 ? void 0 : error.message) || String(error)));
                res.status(((_a = error === null || error === void 0 ? void 0 : error.response) === null || _a === void 0 ? void 0 : _a.status) || 500).json(((_b = error === null || error === void 0 ? void 0 : error.response) === null || _b === void 0 ? void 0 : _b.data) || { detail: error === null || error === void 0 ? void 0 : error.message });
            });
        };
        RED.httpAdmin.get("/noderedhome/" + suburl + "/clearalldevice", handleClearAll);
        RED.httpAdmin.get("/noderedhome/" + this.id + "/clearalldevice", handleClearAll);
        RED.httpAdmin.get("/noderedhome/local/clearalldevice", handleClearAll);
        const handleLogout = (_req, res) => {
            if (!accessToken || accessToken === "local-token") {
                res.sendStatus(200);
                return;
            }
            axios_1.default.request({
                method: 'POST',
                url: serverUrl + '/api/v1/logout',
                headers: {
                    'content-type': 'application/json',
                    'Authorization': "Bearer " + accessToken
                },
                data: {
                    token: accessToken
                }
            })
                .then(() => {
                this.trace("Token deleted on gateway successfully (Logout)");
                res.sendStatus(200);
            })
                .catch((error) => {
                var _a, _b;
                this.debug("Error when logging out on gateway: " + ((error === null || error === void 0 ? void 0 : error.message) || String(error)));
                res.status(((_a = error === null || error === void 0 ? void 0 : error.response) === null || _a === void 0 ? void 0 : _a.status) || 500).json(((_b = error === null || error === void 0 ? void 0 : error.response) === null || _b === void 0 ? void 0 : _b.data) || { detail: error === null || error === void 0 ? void 0 : error.message });
            });
        };
        RED.httpAdmin.post("/noderedhome/" + this.id + "/logout", handleLogout);
        RED.httpAdmin.post("/noderedhome/local/logout", handleLogout);
        RED.httpAdmin.get("/noderedhome/" + this.id + "/getfullconfig", (_req, res) => {
            axios_1.default.request({
                method: 'GET',
                url: serverUrl + '/v1.0/user/devices',
                headers: {
                    'content-type': 'application/json',
                    'Authorization': "Bearer " + accessToken
                }
            })
                .then(result => {
                this.trace("Full Alice SmartHome config successfully retrieved");
                res.json(result.data);
            })
                .catch(error => {
                this.debug("Error when retrieve Alice SmartHome config: " + error.message);
                res.sendStatus(500);
            });
        });
        this.isOnline = false;
        let ws = null;
        let closing = false;
        let reconnectDelay = RECONNECT_MIN_MS;
        let reconnectTimer = null;
        let watchdogTimer = null;
        const stopWatchdog = () => {
            if (watchdogTimer) {
                clearTimeout(watchdogTimer);
                watchdogTimer = null;
            }
        };
        const resetWatchdog = () => {
            stopWatchdog();
            watchdogTimer = setTimeout(() => {
                watchdogTimer = null;
                this.debug("WS watchdog: no activity for " + WATCHDOG_TIMEOUT_MS + "ms, terminating connection");
                if (ws) {
                    ws.terminate();
                }
            }, WATCHDOG_TIMEOUT_MS);
        };
        const scheduleReconnect = () => {
            if (closing || reconnectTimer) {
                return;
            }
            const delay = reconnectDelay + Math.floor(Math.random() * RECONNECT_JITTER_MS);
            reconnectDelay = Math.min(reconnectDelay * 2, RECONNECT_MAX_MS);
            this.debug("WS reconnect scheduled in " + delay + "ms");
            reconnectTimer = setTimeout(() => {
                reconnectTimer = null;
                connect();
            }, delay);
        };
        const connect = () => {
            if (closing) {
                return;
            }
            this.debug("Connecting to WS gateway: " + wsUrl);
            const socket = new ws_1.default(wsUrl, {
                headers: { Authorization: "Bearer " + accessToken },
                handshakeTimeout: HANDSHAKE_TIMEOUT_MS
            });
            ws = socket;
            socket.on("open", () => {
                this.debug("WS connection opened, waiting for hello");
                resetWatchdog();
            });
            socket.on("ping", () => {
                resetWatchdog();
            });
            socket.on("message", (raw) => {
                resetWatchdog();
                let frame;
                try {
                    frame = JSON.parse(raw.toString());
                }
                catch (_err) {
                    this.warn("WS: invalid JSON frame ignored");
                    return;
                }
                if (!frame || typeof frame !== "object") {
                    this.warn("WS: unexpected frame ignored");
                    return;
                }
                switch (frame.type) {
                    case "hello":
                        this.debug("WS gateway connected (hello received)");
                        reconnectDelay = RECONNECT_MIN_MS;
                        this.emit('online');
                        break;
                    case "command":
                        this.trace("Incoming command devId:" + frame.devId + " timestamp:" + new Date().getTime());
                        if (!Array.isArray(frame.payload)) {
                            this.warn("WS: command frame without payload array ignored. devId:" + frame.devId);
                            return;
                        }
                        if (frame.devId) {
                            try {
                                this.emit(String(frame.devId), frame.payload);
                            }
                            catch (err) {
                                this.warn("WS: command listener error: " + (err instanceof Error ? err.message : String(err)));
                            }
                        }
                        break;
                    case "message":
                        if (typeof frame.text === "string") {
                            this.warn(frame.text);
                        }
                        else {
                            this.trace("WS: message frame without text ignored");
                        }
                        break;
                    default:
                        this.trace("WS: unknown frame type ignored: " + frame.type);
                }
            });
            socket.on("unexpected-response", (req, res) => {
                stopWatchdog();
                if (res.statusCode === 401 || res.statusCode === 403) {
                    this.error("WS gateway rejected token (" + res.statusCode + "): токен недействителен или не найден на сервере, переавторизуйтесь в настройках ноды");
                }
                else {
                    this.debug("WS unexpected server response: HTTP " + res.statusCode);
                }
                req.destroy();
                if (ws === socket) {
                    ws = null;
                }
                this.emit('offline');
                scheduleReconnect();
            });
            socket.on("error", (err) => {
                this.debug("WS error: " + err.message);
            });
            socket.on("close", (code, reason) => {
                stopWatchdog();
                if (code === 4429) {
                    this.warn("WS gateway closed connection (4429): превышен лимит подключений — не более 5 на пользователя");
                }
                else if (code === 4401) {
                    this.error("WS gateway closed connection (4401): токен не найден или отозван сервером, переавторизуйтесь в настройках ноды");
                }
                this.debug("WS connection closed. code:" + code + " reason:" + reason.toString());
                if (ws === socket) {
                    ws = null;
                }
                this.emit('offline');
                scheduleReconnect();
            });
        };
        connect();
        this.on('offline', () => {
            this.isOnline = false;
        });
        this.on('online', () => {
            this.isOnline = true;
        });
        this.on('close', (done) => {
            closing = true;
            if (reconnectTimer) {
                clearTimeout(reconnectTimer);
                reconnectTimer = null;
            }
            stopWatchdog();
            this.emit('offline');
            const socket = ws;
            ws = null;
            if (!socket || socket.readyState === ws_1.default.CLOSED) {
                done();
                return;
            }
            let doneCalled = false;
            const finish = () => {
                if (!doneCalled) {
                    doneCalled = true;
                    done();
                }
            };
            socket.once('close', finish);
            try {
                socket.close(1000);
            }
            catch (_err) {
                socket.terminate();
            }
            setTimeout(() => {
                if (socket.readyState !== ws_1.default.CLOSED) {
                    socket.terminate();
                }
                finish();
            }, CLOSE_FAILSAFE_MS).unref();
        });
        this.send2gate = (path, data, _retain) => {
            this.trace("Outgoing: " + path);
            const arrPath = path.split('/');
            const devId = arrPath[arrPath.length - 1];
            if (!ws || ws.readyState !== ws_1.default.OPEN) {
                this.debug("WS not connected, command_result dropped. devId:" + devId);
                return;
            }
            let payload;
            try {
                payload = JSON.parse(data);
            }
            catch (_err) {
                this.warn("send2gate: invalid JSON data ignored. devId:" + devId);
                return;
            }
            ws.send(JSON.stringify({ v: 1, type: "command_result", devId: devId, payload: payload }));
        };
        this.getToken = () => {
            return accessToken;
        };
    }
    RED.nodes.registerType("alice-service", AliceService, {
        credentials: {
            email: { type: "text" },
            password: { type: "password" },
            token: { type: "password" },
            id: { type: "text" }
        }
    });
};
//# sourceMappingURL=alice.js.map