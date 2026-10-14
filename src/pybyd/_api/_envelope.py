"""Shared envelope building for token-authenticated requests."""

from __future__ import annotations

import json
import time
from typing import Any

from pybyd._crypto.aes import aes_encrypt_hex
from pybyd._crypto.hashing import compute_checkcode, compute_cn_checkcode, sha1_mixed
from pybyd._crypto.signing import build_sign_string
from pybyd.config import BydConfig
from pybyd.session import Session


def _add_cn_device_fields(config: BydConfig, payload: dict[str, Any]) -> dict[str, Any]:
    """Add CN device fields and compute CN checkcode (SHA-256)."""
    payload["ostype"] = config.device.ostype
    payload["imei"] = config.device.imei
    payload["mac"] = config.device.mac
    payload["model"] = config.device.model
    payload["sdk"] = config.device.sdk
    payload["serviceTime"] = str(int(time.time() * 1000))
    payload["mod"] = config.device.mod
    payload["checkcode"] = compute_cn_checkcode(payload)
    return payload


def build_token_outer_envelope(
    config: BydConfig,
    session: Session,
    inner: dict[str, str],
    now_ms: int,
    *,
    user_type: str | None = None,
) -> tuple[dict[str, Any], str]:
    """Build a signed outer envelope for post-login requests.

    Parameters
    ----------
    config : BydConfig
        Client configuration.
    session : Session
        Authenticated session with tokens.
    inner : dict
        Inner payload fields to encrypt.
    now_ms : int
        Current time in milliseconds since epoch.

    Returns
    -------
    tuple[dict, str]
        (outer_payload, content_key) tuple. The content_key is needed
        to decrypt the response's ``respondData``.
    """
    req_timestamp = str(now_ms)

    content_key = session.content_key()
    sign_key = session.sign_key()

    encry_data = aes_encrypt_hex(
        json.dumps(inner, separators=(",", ":"), ensure_ascii=False),
        content_key,
    )

    if config.is_cn:
        cn_identifier = session.super_id or session.user_id
        id_type = 0 if inner.get("vin") else 2
        sign_fields: dict[str, Any] = {
            **inner,
            "appChannel": config.app_channel,
            "identifier": cn_identifier,
            "identifierType": id_type,
            "imeiMD5": config.device.imei_md5,
            "reqTimestamp": req_timestamp,
            "targetBrand": config.target_brand,
            "vehicleBrand": config.vehicle_brand,
        }
        if inner.get("vin"):
            sign_fields["objective"] = inner["vin"]
        sign = sha1_mixed(build_sign_string(sign_fields, sign_key))
        outer: dict[str, Any] = {
            "appChannel": config.app_channel,
            "encryData": encry_data,
            "identifier": cn_identifier,
            "identifierType": id_type,
            "imeiMD5": config.device.imei_md5,
            "objective": inner.get("vin"),
            "outModelTypes": None,
            "reqTimestamp": req_timestamp,
            "sign": sign,
            "softType": None,
            "targetBrand": config.target_brand,
            "vehicleBrand": config.vehicle_brand,
            "version": None,
        }
        _add_cn_device_fields(config, outer)
        return outer, content_key

    sign_fields = {
        **inner,
        "countryCode": config.country_code,
        "identifier": session.user_id,
        "imeiMD5": config.device.imei_md5,
        "language": config.language,
        "reqTimestamp": req_timestamp,
    }
    sign = sha1_mixed(build_sign_string(sign_fields, sign_key))

    outer = {
        "countryCode": config.country_code,
        "encryData": encry_data,
        "identifier": session.user_id,
        "imeiMD5": config.device.imei_md5,
        "language": config.language,
        "reqTimestamp": req_timestamp,
        "sign": sign,
        "ostype": config.device.ostype,
        "imei": config.device.imei,
        "mac": config.device.mac,
        "model": config.device.model,
        "sdk": config.device.sdk,
        "mod": config.device.mod,
        "serviceTime": str(int(time.time() * 1000)),
    }
    if user_type is not None:
        outer["userType"] = user_type
    outer["checkcode"] = compute_checkcode(outer)

    return outer, content_key
