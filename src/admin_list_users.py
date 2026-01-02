import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

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
        if not s:
            return []
        # comma-separated is enough for our use here
        if s.startswith("[") and s.endswith("]"):
            s = s[1:-1]
        return [g.strip().strip('"').strip("'") for g in s.split(",") if g.strip()]

    return []


def _is_admin_caller(event: Dict[str, Any]) -> bool:
    return ADMIN_GROUP in _extract_groups_from_event(event)


def _qs(event: Dict[str, Any], key: str) -> Optional[str]:
    q = event.get("queryStringParameters") or {}
    v = q.get(key)
    if v is None:
        return None
    s = str(v).strip()
    return s or None


def _user_attr_map(user: Dict[str, Any]) -> Dict[str, str]:
    attrs = user.get("Attributes") or []
    out: Dict[str, str] = {}
    for a in attrs:
        name = a.get("Name")
        val = a.get("Value")
        if name:
            out[str(name)] = "" if val is None else str(val)
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
            n = (g.get("GroupName") or "").strip()
            if n:
                groups.append(n)

        token = resp.get("NextToken")
        if not token:
            break

    return groups


def _is_admin_user(username: str) -> bool:
    try:
        return ADMIN_GROUP in _list_groups_for_user(username)
    except Exception as e:
        # If we cannot read groups, be conservative: treat as admin? or non-admin?
        # Better: treat as admin to avoid leaking; but it may hide users unexpectedly.
        log.warning("Cannot list groups for user=%s: %s", username, e)
        return True


def lambda_handler(event, context):
    """
    GET /admin/users?limit=50&paginationToken=...

    Returns ONLY users that are NOT in ADMIN_GROUP.
    NOTE: Cognito ListUsers doesn't include groups; we must check per user.
    """
    if not _is_admin_caller(event):
        return _resp(403, {"error": "forbidden", "detail": "admin_only"})

    limit_s = _qs(event, "limit")
    token_in = _qs(event, "paginationToken")

    limit = 50
    if limit_s:
        try:
            limit = max(1, min(60, int(limit_s)))  # keep it sane
        except ValueError:
            return _resp(400, {"error": "invalid_limit"})

    # We'll fetch pages from Cognito until we collected `limit` non-admins, or Cognito ends.
    out_users: List[Dict[str, Any]] = []
    next_token = token_in

    while len(out_users) < limit:
        kwargs = {"UserPoolId": USER_POOL_ID, "Limit": 60}  # upper bound per call
        if next_token:
            kwargs["PaginationToken"] = next_token

        resp = cognito.list_users(**kwargs)
        next_token = resp.get("PaginationToken")

        for u in resp.get("Users") or []:
            username = u.get("Username")
            if not username:
                continue

            if _is_admin_user(username):
                continue

            attrs = _user_attr_map(u)
            out_users.append(
                {
                    "username": username,
                    "email": attrs.get("email"),
                    "enabled": bool(u.get("Enabled")),
                    "status": u.get("UserStatus"),
                    "created": u.get("UserCreateDate").isoformat() if u.get("UserCreateDate") else None,
                    "modified": u.get("UserLastModifiedDate").isoformat() if u.get("UserLastModifiedDate") else None,
                }
            )

            if len(out_users) >= limit:
                break

        if not next_token:
            break

    return _resp(
        200,
        {
            "items": out_users,
            "nextPaginationToken": next_token,  # use this to continue; may be null/None
        },
    )
