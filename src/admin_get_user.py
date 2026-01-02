import json
import logging
import os
from typing import Any, Dict, List, Optional

import boto3

log = logging.getLogger()
log.setLevel(logging.INFO)

cognito = boto3.client("cognito-idp")

USER_POOL_ID = os.environ["USER_POOL_ID"]
ADMIN_GROUP = os.environ.get("ADMIN_GROUP", "admins")


def _resp(status: int, payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "statusCode": status,
        "headers": {"content-type": "application/json"},
        "body": json.dumps(payload),
    }


def _extract_groups_from_event(event: Dict[str, Any]) -> List[str]:
    rc = event.get("requestContext") or {}
    authorizer = rc.get("authorizer") or {}
    jwt = authorizer.get("jwt") or {}
    claims = jwt.get("claims") or {}
    raw = claims.get("cognito:groups") or claims.get("groups")
    if not raw:
        return []
    if isinstance(raw, list):
        return [str(x).strip() for x in raw if str(x).strip()]
    if isinstance(raw, str):
        s = raw.strip()
        if s.startswith("[") and s.endswith("]"):
            s = s[1:-1]
        return [g.strip().strip('"').strip("'") for g in s.split(",") if g.strip()]
    return []


def _is_admin_caller(event: Dict[str, Any]) -> bool:
    return ADMIN_GROUP in _extract_groups_from_event(event)


def _path_param(event: Dict[str, Any], key: str) -> Optional[str]:
    pp = event.get("pathParameters") or {}
    v = pp.get(key)
    if v is None:
        return None
    s = str(v).strip()
    return s or None


def _attrs_to_map(attrs: List[Dict[str, Any]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for a in attrs or []:
        n = a.get("Name")
        v = a.get("Value")
        if n:
            out[str(n)] = "" if v is None else str(v)
    return out


def _list_groups_for_user(username: str) -> List[str]:
    groups: List[str] = []
    token: Optional[str] = None
    while True:
        kwargs = {"UserPoolId": USER_POOL_ID, "Username": username}
        if token:
            kwargs["NextToken"] = token
        resp = cognito.admin_list_groups_for_user(**kwargs)
        for g in resp.get("Groups") or []:
            name = (g.get("GroupName") or "").strip()
            if name:
                groups.append(name)
        token = resp.get("NextToken")
        if not token:
            break
    return groups


def lambda_handler(event, context):
    """
    GET /admin/users/{username}
    """
    if not _is_admin_caller(event):
        return _resp(403, {"error": "forbidden", "detail": "admin_only"})

    username = _path_param(event, "username")
    if not username:
        return _resp(400, {"error": "missing_username"})

    try:
        u = cognito.admin_get_user(UserPoolId=USER_POOL_ID, Username=username)
        groups = _list_groups_for_user(username)
        attrs = _attrs_to_map(u.get("UserAttributes") or [])

        payload = {
            "username": u.get("Username") or username,
            "enabled": bool(u.get("Enabled")),
            "status": u.get("UserStatus"),
            "created": u.get("UserCreateDate").isoformat() if u.get("UserCreateDate") else None,
            "modified": u.get("UserLastModifiedDate").isoformat() if u.get("UserLastModifiedDate") else None,
            "attributes": attrs,
            "groups": groups,
            "isAdmin": ADMIN_GROUP in groups,
        }
        return _resp(200, payload)

    except cognito.exceptions.UserNotFoundException:
        return _resp(404, {"error": "user_not_found"})
    except Exception as e:
        log.exception("admin_get_user failed")
        return _resp(500, {"error": "internal_error", "detail": str(e)})
