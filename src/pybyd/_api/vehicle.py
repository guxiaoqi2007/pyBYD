"""Vehicle list endpoint.

Endpoints:
  - Overseas: /app/account/getAllListByUserId
  - CN:       /app/auth/getAllListByUserId
"""

from __future__ import annotations

from typing import Any

from pybyd._api._common import build_inner_base, post_token_json
from pybyd._transport import Transport
from pybyd.config import BydConfig
from pybyd.models.vehicle import Vehicle
from pybyd.session import Session

_CN_ENDPOINT = "/app/auth/getAllListByUserId"
_OS_ENDPOINT = "/app/account/getAllListByUserId"


async def fetch_vehicle_list(
    config: BydConfig,
    session: Session,
    transport: Transport,
) -> list[Vehicle]:
    """Fetch all vehicles associated with the authenticated user."""
    endpoint = _CN_ENDPOINT if config.is_cn else _OS_ENDPOINT
    inner = build_inner_base(config)
    decoded = await post_token_json(
        endpoint=endpoint,
        config=config,
        session=session,
        transport=transport,
        inner=inner,
    )
    if isinstance(decoded, list):
        items = decoded
    elif isinstance(decoded, dict) and isinstance(decoded.get("diLinkAutoInfoList"), list):
        items = decoded["diLinkAutoInfoList"]
    else:
        items = []
    return [Vehicle.model_validate(item) for item in items if isinstance(item, dict) and item.get("vin")]
