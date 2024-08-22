# -*- coding: utf-8 -*-
from datetime import datetime
from calendar import timegm
import jwt
import logging
from typing import Any, Dict, Iterable, Optional

import ckan.plugins as plugins
import ckan.model as model
from ckan.common import config
from ckan.logic.schema import default_create_api_token_schema
from ckan.exceptions import CkanConfigurationException
from ckan.types import Schema

log = logging.getLogger(__name__)

CONFIG_ENCODE_SECRET = "api_token.jwt.encode.secret"
CONFIG_DECODE_SECRET = "api_token.jwt.decode.secret"
CONFIG_SECRET_FALLBACK = "SECRET_KEY"
CONFIG_ALGORITHM = "api_token.jwt.algorithm"

def _get_plugins() -> Iterable[plugins.IApiToken]:
    return plugins.PluginImplementations(plugins.IApiToken)

def _get_algorithm() -> str:
    return config.get(CONFIG_ALGORITHM)

def _get_secret(encode: bool) -> str:
    config_key = CONFIG_ENCODE_SECRET if encode else CONFIG_DECODE_SECRET
    secret = config.get(config_key) or f"string:{config.get(CONFIG_SECRET_FALLBACK)}"
    secret_type, value = secret.split(":", 1)
    if secret_type == "file":
        try:
            with open(value, "r") as key_file:
                value = key_file.read().strip()
        except FileNotFoundError:
            raise CkanConfigurationException(f"Secret file {value} not found.")
    if not value:
        raise CkanConfigurationException(f"Neither `{config_key}` nor `{CONFIG_SECRET_FALLBACK}` specified. Missing secret key is a critical security issue.")
    return value

def into_seconds(dt: datetime) -> int:
    return timegm(dt.timetuple())

def get_schema() -> Schema:
    schema = default_create_api_token_schema()
    for plugin in _get_plugins():
        schema = plugin.create_api_token_schema(schema)
    return schema

def postprocess(data: Dict[str, Any], jti: str, data_dict: Dict[str, Any]) -> Dict[str, Any]:
    for plugin in _get_plugins():
        data = plugin.postprocess_api_token(data, jti, data_dict)
    return data

def decode(encoded: str, **kwargs: Any) -> Optional[Dict[str, Any]]:
    for plugin in _get_plugins():
        data = plugin.decode_api_token(encoded, **kwargs)
        if data:
            break
    else:
        try:
            data = jwt.decode(encoded, _get_secret(encode=False), algorithms=[_get_algorithm()], **kwargs)
        except jwt.InvalidTokenError as e:
            log.error("Cannot decode JWT token: %s", e)
            data = None
    return data

def encode(data: Dict[str, Any], **kwargs: Any) -> str:
    for plugin in _get_plugins():
        token = plugin.encode_api_token(data, **kwargs)
        if token:
            break
    else:
        token = jwt.encode(data, _get_secret(encode=True), algorithm=_get_algorithm(), **kwargs)
    return token

def add_extra(result: Dict[str, Any]) -> Dict[str, Any]:
    for plugin in _get_plugins():
        result = plugin.add_extra_fields(result)
    return result

def get_user_from_token(token: str, update_access_time: bool = True) -> Optional[model.User]:
    data = decode(token)
    if not data:
        return None
    for plugin in reversed(list(_get_plugins())):
        data = plugin.preprocess_api_token(data)
    if not data or "jti" not in data:
        return None
    token_obj = model.ApiToken.get(data["jti"])
    if not token_obj:
        return None
    if update_access_time:
        token_obj.touch(update_access_time)
    return token_obj.owner
