"""
Обработчик и валидатор спецификаций Яндекс Умного Дома.
Соответствует официальной документации:
- https://yandex.ru/dev/dialogs/smart-home/doc/ru/concepts/capability-types
- https://yandex.ru/dev/dialogs/smart-home/doc/ru/concepts/on_off
- https://yandex.ru/dev/dialogs/smart-home/doc/ru/concepts/color_setting
- https://yandex.ru/dev/dialogs/smart-home/doc/ru/concepts/mode-instance
- https://yandex.ru/dev/dialogs/smart-home/doc/ru/concepts/mode-instance-modes
- https://yandex.ru/dev/dialogs/smart-home/doc/ru/concepts/range-instance
- https://yandex.ru/dev/dialogs/smart-home/doc/ru/concepts/toggle-instance
- https://yandex.ru/dev/dialogs/smart-home/doc/ru/concepts/video_stream
"""

from typing import Dict, Any, List, Optional, Tuple
import logging

logger = logging.getLogger("smart_home_gateway")

# Допустимые инстансы для умения mode
VALID_MODE_INSTANCES = {
    "cleanup_mode",
    "coffee_mode",
    "dishwashing",
    "fan_speed",
    "heat",
    "input_source",
    "program",
    "swing",
    "tea_mode",
    "thermostat",
    "ventilation_mode",
    "work_speed",
}

# Допустимые инстансы для умения range
VALID_RANGE_INSTANCES = {
    "brightness",
    "temperature",
    "volume",
    "channel",
    "open",
    "humidity",
}

# Допустимые инстансы для умения toggle
VALID_TOGGLE_INSTANCES = {
    "backlight",
    "controls_locked",
    "ionization",
    "keep_warm",
    "mute",
    "oscillation",
    "pause",
}

# Допустимые инстансы состояния для умения color_setting
VALID_COLOR_INSTANCES = {"rgb", "temperature_k", "hsv", "scene"}


class YandexSpecHandler:
    """Универсальный нормализатор и обработчик умений и свойств Яндекс УД."""

    # -----------------------------------------------------------------
    # 1. DISCOVERY (GET /v1.0/user/devices)
    # -----------------------------------------------------------------

    @classmethod
    def normalize_capability_discovery(cls, raw_cap: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Нормализует умение для ответа Discovery:
        - Исключает служебные поля (id, state, response)
        - Для on_off оставляет только split (instance запрещен в parameters)
        - Для color_setting проверяет color_model, temperature_k, color_scene (instance запрещен)
        - Для mode гарантирует массив modes: [{"value": ...}] и валидный instance
        - Для range валидирует range {min, max, precision} и убирает фиктивные unit
        - Для video_stream гарантирует retrievable: False, reportable: False
        """
        if not isinstance(raw_cap, dict):
            return None

        cap_type = raw_cap.get("type", "")
        if not cap_type.startswith("devices.capabilities."):
            return None

        retrievable = bool(raw_cap.get("retrievable", True))
        reportable = bool(raw_cap.get("reportable", True))
        raw_params = raw_cap.get("parameters", {}) if isinstance(raw_cap.get("parameters"), dict) else {}

        # 1. on_off
        if cap_type == "devices.capabilities.on_off":
            split_val = bool(raw_params.get("split", False))
            params: Dict[str, Any] = {}
            if split_val:
                params["split"] = True
            res = {
                "type": cap_type,
                "retrievable": retrievable,
                "reportable": reportable,
            }
            if params:
                res["parameters"] = params
            return res

        # 2. video_stream
        if cap_type == "devices.capabilities.video_stream":
            protocols = raw_params.get("protocols")
            if not isinstance(protocols, list) or not protocols:
                protocols = ["hls"]
            return {
                "type": cap_type,
                "retrievable": False,
                "reportable": False,
                "parameters": {
                    "protocols": protocols
                }
            }

        # 3. color_setting
        if cap_type == "devices.capabilities.color_setting":
            params = {}
            # color_model
            cm = raw_params.get("color_model")
            if cm in ("rgb", "hsv"):
                params["color_model"] = cm
            elif raw_params.get("scheme") in ("rgb", "rgb_normal", "hsv"):
                s = raw_params.get("scheme")
                params["color_model"] = "rgb" if s in ("rgb", "rgb_normal") else "hsv"

            # temperature_k
            temp_k = raw_params.get("temperature_k")
            if isinstance(temp_k, dict) and "min" in temp_k and "max" in temp_k:
                try:
                    t_min = max(2000, int(temp_k.get("min", 2000)))
                    t_max = min(9000, int(temp_k.get("max", 9000)))
                    if t_min > t_max:
                        t_min, t_max = 2000, 9000
                    params["temperature_k"] = {"min": t_min, "max": t_max}
                except (ValueError, TypeError):
                    pass

            # color_scene
            cs = raw_params.get("color_scene")
            scenes_list = []
            if isinstance(cs, dict) and isinstance(cs.get("scenes"), list):
                for s in cs["scenes"]:
                    sid = s.get("id") if isinstance(s, dict) else str(s)
                    if sid:
                        scenes_list.append({"id": str(sid)})
            elif isinstance(cs, list):
                for sid in cs:
                    if sid:
                        scenes_list.append({"id": str(sid)})

            if scenes_list:
                params["color_scene"] = {"scenes": scenes_list}

            # Если ничего не было указано - по умолчанию RGB
            if not params:
                params["color_model"] = "rgb"

            return {
                "type": cap_type,
                "retrievable": retrievable,
                "reportable": reportable,
                "parameters": params
            }

        # 4. mode
        if cap_type == "devices.capabilities.mode":
            inst = raw_params.get("instance") or "program"
            if inst not in VALID_MODE_INSTANCES:
                inst = "program"

            raw_modes = raw_params.get("modes", [])
            clean_modes = []
            if isinstance(raw_modes, list):
                for m in raw_modes:
                    val = m.get("value") if isinstance(m, dict) else str(m)
                    if val and val not in [x["value"] for x in clean_modes]:
                        clean_modes.append({"value": str(val)})

            if not clean_modes:
                clean_modes = [{"value": "auto"}]

            return {
                "type": cap_type,
                "retrievable": retrievable,
                "reportable": reportable,
                "parameters": {
                    "instance": inst,
                    "modes": clean_modes
                }
            }

        # 5. range
        if cap_type == "devices.capabilities.range":
            inst = raw_params.get("instance") or "brightness"
            if inst not in VALID_RANGE_INSTANCES:
                inst = "brightness"

            range_obj = raw_params.get("range", {})
            try:
                r_min = float(range_obj.get("min", 0))
                r_max = float(range_obj.get("max", 100))
                r_prec = float(range_obj.get("precision", 1))
            except (ValueError, TypeError):
                r_min, r_max, r_prec = 0.0, 100.0, 1.0

            if r_min > r_max:
                r_min, r_max = 0.0, 100.0
            if r_prec <= 0:
                r_prec = 1.0

            # Преобразуем в int, если целые
            min_val = int(r_min) if r_min.is_integer() else r_min
            max_val = int(r_max) if r_max.is_integer() else r_max
            prec_val = int(r_prec) if r_prec.is_integer() else r_prec

            params = {
                "instance": inst,
                "random_access": bool(raw_params.get("random_access", True)),
                "range": {
                    "min": min_val,
                    "max": max_val,
                    "precision": prec_val
                }
            }

            unit = raw_params.get("unit")
            if unit and unit != "unit.number":
                params["unit"] = str(unit)
            elif inst == "brightness" or inst == "humidity" or inst == "open":
                params["unit"] = "unit.percent"
            elif inst == "temperature" and not unit:
                params["unit"] = "unit.temperature.celsius"

            return {
                "type": cap_type,
                "retrievable": retrievable,
                "reportable": reportable,
                "parameters": params
            }

        # 6. toggle
        if cap_type == "devices.capabilities.toggle":
            inst = raw_params.get("instance") or "mute"
            if inst not in VALID_TOGGLE_INSTANCES:
                inst = "mute"

            return {
                "type": cap_type,
                "retrievable": retrievable,
                "reportable": reportable,
                "parameters": {
                    "instance": inst
                }
            }

        # Прочие умения
        res = {
            "type": cap_type,
            "retrievable": retrievable,
            "reportable": reportable,
        }
        if raw_params:
            res["parameters"] = raw_params
        return res

    @classmethod
    def normalize_property_discovery(cls, raw_prop: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Нормализует датчик/свойство для ответа Discovery."""
        if not isinstance(raw_prop, dict):
            return None

        prop_type = raw_prop.get("type", "")
        if not prop_type.startswith("devices.properties."):
            return None

        retrievable = bool(raw_prop.get("retrievable", True))
        reportable = bool(raw_prop.get("reportable", True))
        raw_params = raw_prop.get("parameters", {}) if isinstance(raw_prop.get("parameters"), dict) else {}

        res = {
            "type": prop_type,
            "retrievable": retrievable,
            "reportable": reportable,
        }
        if raw_params:
            res["parameters"] = raw_params
        return res

    # -----------------------------------------------------------------
    # 2. QUERY (POST /v1.0/user/devices/query)
    # -----------------------------------------------------------------

    @classmethod
    def normalize_capability_query_state(cls, cap: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Форматирует состояние умения строго по спецификации:
        - Исключает retrievable: False
        - Строго типизирует значения (bool, int/float, str, dict)
        - Проверяет границы range и допустимость режимов
        - Гарантирует правильный инстанс для color_setting
        """
        if cap.get("retrievable") is False:
            return None

        cap_type = cap.get("type", "")
        params = cap.get("parameters", {}) if isinstance(cap.get("parameters"), dict) else {}
        st = cap.get("state")
        raw_inst = st.get("instance") if isinstance(st, dict) else None
        raw_val = st.get("value") if isinstance(st, dict) else None

        # 1. on_off
        if cap_type == "devices.capabilities.on_off":
            return {
                "type": cap_type,
                "state": {
                    "instance": "on",
                    "value": bool(raw_val) if raw_val is not None else False
                }
            }

        # 2. toggle
        if cap_type == "devices.capabilities.toggle":
            inst = raw_inst or params.get("instance") or "mute"
            return {
                "type": cap_type,
                "state": {
                    "instance": inst,
                    "value": bool(raw_val) if raw_val is not None else False
                }
            }

        # 3. range
        if cap_type == "devices.capabilities.range":
            inst = raw_inst or params.get("instance") or "brightness"
            r_obj = params.get("range", {})
            min_v = r_obj.get("min", 0)
            max_v = r_obj.get("max", 100)

            try:
                num = float(raw_val) if ("." in str(raw_val) or isinstance(raw_val, float)) else int(raw_val)
            except (ValueError, TypeError):
                num = min_v

            if min_v is not None and num < min_v:
                num = min_v
            if max_v is not None and num > max_v:
                num = max_v

            # Преобразуем в int, если целое число
            if isinstance(num, float) and num.is_integer():
                num = int(num)

            return {
                "type": cap_type,
                "state": {
                    "instance": inst,
                    "value": num
                }
            }

        # 4. mode
        if cap_type == "devices.capabilities.mode":
            inst = raw_inst or params.get("instance") or "program"
            modes = params.get("modes", [])
            valid_modes = [m.get("value") if isinstance(m, dict) else str(m) for m in modes]

            val_str = str(raw_val) if raw_val is not None else ""
            if valid_modes:
                if val_str not in valid_modes:
                    val_str = valid_modes[0]
            else:
                if not val_str:
                    val_str = "auto"

            return {
                "type": cap_type,
                "state": {
                    "instance": inst,
                    "value": val_str
                }
            }

        # 5. color_setting
        if cap_type == "devices.capabilities.color_setting":
            inst = raw_inst
            if inst not in VALID_COLOR_INSTANCES:
                # Автовыбор активного инстанса по доступным параметрам
                if "temperature_k" in params:
                    inst = "temperature_k"
                elif "color_model" in params:
                    inst = params.get("color_model", "rgb")
                elif "color_scene" in params:
                    inst = "scene"
                else:
                    inst = "rgb"

            if inst == "rgb":
                try:
                    val = int(raw_val) & 0xFFFFFF if raw_val is not None else 16777215
                except (ValueError, TypeError):
                    val = 16777215
                return {
                    "type": cap_type,
                    "state": {"instance": "rgb", "value": val}
                }

            elif inst == "temperature_k":
                t_params = params.get("temperature_k", {})
                t_min = t_params.get("min", 2000)
                t_max = t_params.get("max", 9000)
                try:
                    val = int(raw_val) if raw_val is not None else 4500
                    if val < t_min:
                        val = t_min
                    if val > t_max:
                        val = t_max
                except (ValueError, TypeError):
                    val = 4500 if t_min <= 4500 <= t_max else t_min
                return {
                    "type": cap_type,
                    "state": {"instance": "temperature_k", "value": val}
                }

            elif inst == "hsv":
                if isinstance(raw_val, dict):
                    h = raw_val.get("h", 0)
                    s = raw_val.get("s", 0)
                    v = raw_val.get("v", 100)
                    try:
                        h = max(0, min(360, int(h)))
                        s = max(0, min(100, int(s)))
                        v = max(0, min(100, int(v)))
                    except (ValueError, TypeError):
                        h, s, v = 0, 0, 100
                else:
                    h, s, v = 0, 0, 100
                return {
                    "type": cap_type,
                    "state": {"instance": "hsv", "value": {"h": h, "s": s, "v": v}}
                }

            elif inst == "scene":
                scenes = params.get("color_scene", {}).get("scenes", [])
                valid_scenes = [s.get("id") if isinstance(s, dict) else str(s) for s in scenes]
                val_scene = str(raw_val) if raw_val is not None else ""
                if valid_scenes:
                    if val_scene not in valid_scenes:
                        val_scene = valid_scenes[0]
                else:
                    if not val_scene:
                        val_scene = "alice"
                return {
                    "type": cap_type,
                    "state": {"instance": "scene", "value": val_scene}
                }

        # 6. video_stream - retrievable: False, никогда не отдается в query
        if cap_type == "devices.capabilities.video_stream":
            return None

        # Прочие умения
        inst = raw_inst or params.get("instance") or "on"
        return {
            "type": cap_type,
            "state": {
                "instance": inst,
                "value": raw_val if raw_val is not None else 0
            }
        }

    @classmethod
    def normalize_property_query_state(cls, prop: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Форматирует состояние свойства/датчика строго по спецификации."""
        if prop.get("retrievable") is False:
            return None

        prop_type = prop.get("type", "")
        params = prop.get("parameters", {}) if isinstance(prop.get("parameters"), dict) else {}
        st = prop.get("state")
        raw_inst = st.get("instance") if isinstance(st, dict) else None
        raw_val = st.get("value") if isinstance(st, dict) else None

        inst = raw_inst or params.get("instance") or "temperature"

        if prop_type == "devices.properties.float":
            try:
                num = float(raw_val) if ("." in str(raw_val) or isinstance(raw_val, float)) else int(raw_val)
            except (ValueError, TypeError):
                num = 0.0
            return {
                "type": prop_type,
                "state": {
                    "instance": inst,
                    "value": num
                }
            }
        elif prop_type == "devices.properties.event":
            return {
                "type": prop_type,
                "state": {
                    "instance": inst,
                    "value": str(raw_val) if raw_val is not None else ""
                }
            }

        return {
            "type": prop_type,
            "state": {
                "instance": inst,
                "value": raw_val if raw_val is not None else 0
            }
        }

    # -----------------------------------------------------------------
    # 3. ACTION (POST /v1.0/user/devices/action)
    # -----------------------------------------------------------------

    @classmethod
    def handle_action_capability(
        cls,
        action_cap: Dict[str, Any],
        saved_caps: List[Dict[str, Any]]
    ) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
        """
        Обрабатывает команду действия от Алисы.
        Возвращает:
        (
            response_capability_dict, # ответ для Яндекса
            state_to_save             # новое состояние для сохранения в БД (или None)
        )
        """
        cap_type = action_cap.get("type", "")
        st = action_cap.get("state", {})
        cap_inst = st.get("instance")
        val = st.get("value")
        relative = bool(st.get("relative", False))

        # Ищем соответствующее умение в конфигурации устройства
        matched_cap = None
        for sc in saved_caps:
            if sc.get("type") != cap_type:
                continue
            # Для color_setting и on_off сопоставление идет только по типу умения
            if cap_type in ("devices.capabilities.color_setting", "devices.capabilities.on_off"):
                matched_cap = sc
                break
            sc_inst = sc.get("parameters", {}).get("instance")
            if cap_inst and sc_inst and sc_inst != cap_inst:
                continue
            matched_cap = sc
            break

        # Если умение не найдено у устройства
        if not matched_cap:
            return {
                "type": cap_type,
                "state": {
                    "instance": cap_inst,
                    "action_result": {
                        "status": "ERROR",
                        "error_code": "NOT_SUPPORTED_IN_CURRENT_MODE",
                        "error_message": f"Умение {cap_type} не поддерживается данным устройством"
                    }
                }
            }, None

        params = matched_cap.get("parameters", {})
        saved_state = matched_cap.get("state", {})

        # 1. video_stream: get_stream
        if cap_type == "devices.capabilities.video_stream":
            if cap_inst == "get_stream":
                v_val = saved_state.get("value") if isinstance(saved_state, dict) else None
                if v_val and isinstance(v_val, dict) and v_val.get("stream_url"):
                    return {
                        "type": cap_type,
                        "state": {
                            "instance": "get_stream",
                            "value": {
                                "stream_url": v_val["stream_url"],
                                "protocol": v_val.get("protocol", "hls")
                            },
                            "action_result": {"status": "DONE"}
                        }
                    }, None
                else:
                    return {
                        "type": cap_type,
                        "state": {
                            "instance": "get_stream",
                            "action_result": {
                                "status": "ERROR",
                                "error_code": "DEVICE_UNREACHABLE",
                                "error_message": "Stream URL is not configured"
                            }
                        }
                    }, None

        # 2. mode: проверка поддерживаемых режимов
        if cap_type == "devices.capabilities.mode":
            modes_list = params.get("modes", [])
            valid_modes = [m.get("value") if isinstance(m, dict) else str(m) for m in modes_list]
            val_str = str(val) if val is not None else ""
            if valid_modes and val_str not in valid_modes:
                return {
                    "type": cap_type,
                    "state": {
                        "instance": cap_inst or params.get("instance", "program"),
                        "action_result": {
                            "status": "ERROR",
                            "error_code": "INVALID_VALUE",
                            "error_message": f"Режим '{val_str}' не поддерживается устройством"
                        }
                    }
                }, None

            return {
                "type": cap_type,
                "state": {
                    "instance": cap_inst or params.get("instance", "program"),
                    "action_result": {"status": "DONE"}
                }
            }, {
                "type": cap_type,
                "state": {
                    "instance": cap_inst or params.get("instance", "program"),
                    "value": val_str
                }
            }

        # 3. range: поддержка относительных команд (relative: true) и ограничений
        if cap_type == "devices.capabilities.range":
            r_obj = params.get("range", {})
            min_v = r_obj.get("min", 0)
            max_v = r_obj.get("max", 100)

            curr_v = saved_state.get("value", min_v)
            try:
                curr_num = float(curr_v) if ("." in str(curr_v) or isinstance(curr_v, float)) else int(curr_v)
            except (ValueError, TypeError):
                curr_num = min_v

            try:
                delta_or_val = float(val) if ("." in str(val) or isinstance(val, float)) else int(val)
            except (ValueError, TypeError):
                delta_or_val = 0

            if relative:
                new_num = curr_num + delta_or_val
            else:
                new_num = delta_or_val

            if min_v is not None and new_num < min_v:
                new_num = min_v
            if max_v is not None and new_num > max_v:
                new_num = max_v

            if isinstance(new_num, float) and new_num.is_integer():
                new_num = int(new_num)

            return {
                "type": cap_type,
                "state": {
                    "instance": cap_inst or params.get("instance", "brightness"),
                    "action_result": {"status": "DONE"}
                }
            }, {
                "type": cap_type,
                "state": {
                    "instance": cap_inst or params.get("instance", "brightness"),
                    "value": new_num
                }
            }

        # 4. color_setting: валидация инстансов и сцен
        if cap_type == "devices.capabilities.color_setting":
            if cap_inst not in VALID_COLOR_INSTANCES:
                return {
                    "type": cap_type,
                    "state": {
                        "instance": cap_inst,
                        "action_result": {
                            "status": "ERROR",
                            "error_code": "INVALID_ACTION",
                            "error_message": f"Недопустимая функция color_setting: {cap_inst}"
                        }
                    }
                }, None

            if cap_inst in ("rgb", "hsv") and "color_model" not in params:
                return {
                    "type": cap_type,
                    "state": {
                        "instance": cap_inst,
                        "action_result": {
                            "status": "ERROR",
                            "error_code": "NOT_SUPPORTED_IN_CURRENT_MODE",
                            "error_message": "Выбор цвета не поддерживается устройством"
                        }
                    }
                }, None

            if cap_inst == "temperature_k" and "temperature_k" not in params:
                return {
                    "type": cap_type,
                    "state": {
                        "instance": cap_inst,
                        "action_result": {
                            "status": "ERROR",
                            "error_code": "NOT_SUPPORTED_IN_CURRENT_MODE",
                            "error_message": "Цветовая температура не поддерживается устройством"
                        }
                    }
                }, None

            if cap_inst == "scene":
                if "color_scene" not in params:
                    return {
                        "type": cap_type,
                        "state": {
                            "instance": "scene",
                            "action_result": {
                                "status": "ERROR",
                                "error_code": "NOT_SUPPORTED_IN_CURRENT_MODE",
                                "error_message": "Световые сценарии не поддерживаются устройством"
                            }
                        }
                    }, None
                scenes_list = params.get("color_scene", {}).get("scenes", [])
                valid_scenes = [s.get("id") if isinstance(s, dict) else str(s) for s in scenes_list]
                val_scene = str(val) if val is not None else ""
                if valid_scenes and val_scene not in valid_scenes:
                    return {
                        "type": cap_type,
                        "state": {
                            "instance": "scene",
                            "action_result": {
                                "status": "ERROR",
                                "error_code": "INVALID_VALUE",
                                "error_message": f"Световой сценарий '{val_scene}' не поддерживается"
                            }
                        }
                    }, None

            return {
                "type": cap_type,
                "state": {
                    "instance": cap_inst,
                    "action_result": {"status": "DONE"}
                }
            }, {
                "type": cap_type,
                "state": {
                    "instance": cap_inst,
                    "value": val
                }
            }

        # 5. on_off
        if cap_type == "devices.capabilities.on_off":
            return {
                "type": cap_type,
                "state": {
                    "instance": "on",
                    "action_result": {"status": "DONE"}
                }
            }, {
                "type": cap_type,
                "state": {
                    "instance": "on",
                    "value": bool(val)
                }
            }

        # 6. toggle
        if cap_type == "devices.capabilities.toggle":
            inst = cap_inst or params.get("instance", "mute")
            return {
                "type": cap_type,
                "state": {
                    "instance": inst,
                    "action_result": {"status": "DONE"}
                }
            }, {
                "type": cap_type,
                "state": {
                    "instance": inst,
                    "value": bool(val)
                }
            }

        # Стандартный ответ для прочих умений
        inst = cap_inst or params.get("instance", "on")
        return {
            "type": cap_type,
            "state": {
                "instance": inst,
                "action_result": {"status": "DONE"}
            }
        }, {
            "type": cap_type,
            "state": {
                "instance": inst,
                "value": val
            }
        }

    # -----------------------------------------------------------------
    # 4. CALLBACK NOTIFY STATE (POST /callback/state)
    # -----------------------------------------------------------------

    @classmethod
    def normalize_callback_state(
        cls,
        caps: Optional[List[Dict[str, Any]]],
        props: Optional[List[Dict[str, Any]]]
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Нормализует исходящие состояния для Yandex state callback:
        - Исключает нерепортируемые типы (video_stream)
        - Строго типизирует значения по схеме
        """
        clean_caps = []
        if caps:
            for c in caps:
                st = c.get("state")
                c_type = c.get("type", "")
                if not st or not isinstance(st, dict) or not c_type:
                    continue
                if c_type == "devices.capabilities.video_stream":
                    continue

                inst = st.get("instance")
                val = st.get("value")

                if c_type == "devices.capabilities.on_off":
                    inst = "on"
                    val = bool(val)
                elif c_type == "devices.capabilities.toggle":
                    inst = inst or "mute"
                    val = bool(val)
                elif c_type == "devices.capabilities.range":
                    inst = inst or "brightness"
                    try:
                        val = float(val) if ("." in str(val) or isinstance(val, float)) else int(val)
                    except (ValueError, TypeError):
                        val = 0
                elif c_type == "devices.capabilities.mode":
                    inst = inst or "program"
                    val = str(val) if val is not None else "auto"
                elif c_type == "devices.capabilities.color_setting":
                    if inst not in VALID_COLOR_INSTANCES:
                        continue

                clean_caps.append({
                    "type": c_type,
                    "state": {
                        "instance": inst,
                        "value": val
                    }
                })

        clean_props = []
        if props:
            for p in props:
                st = p.get("state")
                p_type = p.get("type", "")
                if not st or not isinstance(st, dict) or not p_type:
                    continue

                inst = st.get("instance") or "temperature"
                val = st.get("value")

                if p_type == "devices.properties.float":
                    try:
                        val = float(val) if ("." in str(val) or isinstance(val, float)) else int(val)
                    except (ValueError, TypeError):
                        val = 0.0
                elif p_type == "devices.properties.event":
                    val = str(val) if val is not None else ""

                clean_props.append({
                    "type": p_type,
                    "state": {
                        "instance": inst,
                        "value": val
                    }
                })

        return clean_caps, clean_props
