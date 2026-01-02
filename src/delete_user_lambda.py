import base64
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


def _parse_body(event: Dict[str, Any]) -> Dict[str, Any]:
    body = event.get("body")
    if not body:
        return {}
    if event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode("utf-8")
    if isinstance(body, str):
        return json.loads(body)
    return body


def _resp(status: int, payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "statusCode": status,
        "headers": {"content-type": "application/json"},
        "body": json.dumps(payload),
    }


def _extract_groups(event: Dict[str, Any]) -> List[str]:
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

        if s.startswith("[") and s.endswith("]"):
            try:
                arr = json.loads(s)
                if isinstance(arr, list):
                    return [str(x).strip() for x in arr if str(x).strip()]
            except Exception:
                pass

            inner = s[1:-1].strip()
            if not inner:
                return []
            parts = [p.strip() for p in inner.split(",") if p.strip()]
            cleaned = [p.strip('"').strip("'").strip() for p in parts]
            return [c for c in cleaned if c]

        return [g.strip() for g in s.split(",") if g.strip()]

    return []


def _is_admin_caller(event: Dict[str, Any]) -> bool:
    return ADMIN_GROUP in _extract_groups(event)


def _get_username_from_event(event: Dict[str, Any]) -> Optional[str]:
    # Preferred: path param /users/{username}
    pp = (event.get("pathParameters") or {})
    username = pp.get("username") or pp.get("user") or pp.get("email")
    if username:
        return str(username).strip()

    # Fallback: body { "username": "..."} or { "email": "..." }
    data = _parse_body(event)
    username = data.get("username") or data.get("email")
    if username:
        return str(username).strip()

    # Last fallback: query string ?username=
    qs = (event.get("queryStringParameters") or {})
    username = qs.get("username") or qs.get("email")
    if username:
        return str(username).strip()

    return None


def _user_is_admin(username: str) -> bool:
    """
    Checks if target user is in ADMIN_GROUP.
    If user does not exist, raise cognito.exceptions.UserNotFoundException.
    """
    # This returns a list of group objects
    resp = cognito.admin_list_groups_for_user(UserPoolId=USER_POOL_ID, Username=username)
    groups = resp.get("Groups") or []
    return any(g.get("GroupName") == ADMIN_GROUP for g in groups)


def lambda_handler(event, context):
    """
    DELETE /admin/users/{username}

    Requirements:
    - Must be behind API Gateway HTTP API + JWT authorizer.
    - Caller must be in ADMIN_GROUP.
    - Target user must NOT be in ADMIN_GROUP.

    Returns:
    - 200 {deleted: true, username: ...}
    - 403 if caller not admin
    - 404 if user not found
    - 409 if target user is admin
    """
    rc = event.get("requestContext") or {}
    claims = (((rc.get("authorizer") or {}).get("jwt") or {}).get("claims")) or {}
    log.info("CLAIMS=%s", json.dumps(claims))

    if not _is_admin_caller(event):
        return _resp(403, {"error": "forbidden", "detail": "admin_only"})

    username = _get_username_from_event(event)
    if not username:
        return _resp(400, {"error": "missing_username", "detail": "Provide path param {username} or body.username"})

    try:
        if _user_is_admin(username):
            return _resp(409, {"error": "conflict", "detail": "cannot_delete_admin", "username": username})

        cognito.admin_delete_user(UserPoolId=USER_POOL_ID, Username=username)
        return _resp(200, {"deleted": True, "username": username})

    except cognito.exceptions.UserNotFoundException:
        return _resp(404, {"error": "not_found", "detail": "user_not_found", "username": username})

    except cognito.exceptions.TooManyRequestsException as e:
        return _resp(429, {"error": "too_many_requests", "detail": str(e)})

    except cognito.exceptions.InvalidParameterException as e:
        return _resp(400, {"error": "invalid_parameter", "detail": str(e)})

    except Exception as e:
        return _resp(500, {"error": "internal_error", "detail": str(e)})
