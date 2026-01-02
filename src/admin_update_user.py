import base64
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

# Keep this intentionally strict to avoid accidents.
ALLOWED_ATTRIBUTE_UPDATES = {
    "phone_number",
    "given_name",
    "family_name",
    "name",
    "preferred_username",
    "locale",
    "picture",
    "profile",
    "website",
    "address",
    "birthdate",
    "gender",
    "updated_at",
}
# You *can* update email in Cognito, but because you use email as Username,
# changing it can create confusing states. Keep it blocked by default.
BLOCKED_ATTRIBUTES = {"sub", "email", "email_verified"}


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
    return ADMIN_GROUP in _list_groups_for_user(username)


def _attrs_to_update(attributes: Dict[str, Any]) -> Tuple[List[Dict[str, str]], List[str]]:
    """
    Returns (cognito_attrs, errors)
    """
    errs: List[str] = []
    out: List[Dict[str, str]] = []

    for k, v in (attributes or {}).items():
        name = str(k).strip()
        if not name:
            continue

        if name in BLOCKED_ATTRIBUTES:
            errs.append(f"attribute_not_allowed:{name}")
            continue

        if name not in ALLOWED_ATTRIBUTE_UPDATES and not name.startswith("custom:"):
            errs.append(f"attribute_not_allowed:{name}")
            continue

        if v is None:
            # Cognito doesn't support deleting arbitrary attributes here; ignore None
            continue

        out.append({"Name": name, "Value": str(v)})

    return out, errs


def lambda_handler(event, context):
    """
    PATCH /admin/users/{username}

    body supports:
      attributes: { ... }          # allowed attributes (see whitelist)
      enabled: boolean             # enable/disable user
      resetPassword: boolean       # trigger reset (emails user)
      tempPassword: string         # set password as temporary/permanent
      permanentPassword: boolean   # default False if tempPassword is set
    """
    if not _is_admin_caller(event):
        return _resp(403, {"error": "forbidden", "detail": "admin_only"})

    username = _path_param(event, "username")
    if not username:
        return _resp(400, {"error": "missing_username"})

    # Block updates to admins (business rule)
    try:
        if _is_admin_user(username):
            # 409 because the resource state conflicts with the requested operation (protected user)
            return _resp(409, {"error": "cannot_modify_admin_user"})
    except cognito.exceptions.UserNotFoundException:
        return _resp(404, {"error": "user_not_found"})
    except Exception as e:
        log.exception("group check failed")
        return _resp(500, {"error": "internal_error", "detail": str(e)})

    data = _parse_body(event)

    attributes = data.get("attributes") or {}
    enabled = data.get("enabled", None)
    reset_password = bool(data.get("resetPassword", False))
    temp_password = data.get("tempPassword")
    permanent_password = bool(data.get("permanentPassword", False))

    cognito_attrs, attr_errs = _attrs_to_update(attributes)
    if attr_errs:
        return _resp(400, {"error": "invalid_attributes", "detail": attr_errs})

    try:
        # Update attributes
        if cognito_attrs:
            cognito.admin_update_user_attributes(
                UserPoolId=USER_POOL_ID,
                Username=username,
                UserAttributes=cognito_attrs,
            )

        # Enable/disable
        if enabled is True:
            cognito.admin_enable_user(UserPoolId=USER_POOL_ID, Username=username)
        elif enabled is False:
            cognito.admin_disable_user(UserPoolId=USER_POOL_ID, Username=username)

        # Reset password (Cognito email flow)
        if reset_password:
            cognito.admin_reset_user_password(UserPoolId=USER_POOL_ID, Username=username)

        # Set password explicitly (optional)
        if temp_password:
            cognito.admin_set_user_password(
                UserPoolId=USER_POOL_ID,
                Username=username,
                Password=str(temp_password),
                Permanent=permanent_password,
            )

        # Return fresh detail (no admin users reach here by design)
        u = cognito.admin_get_user(UserPoolId=USER_POOL_ID, Username=username)
        attrs_map = {a["Name"]: a.get("Value") for a in (u.get("UserAttributes") or []) if a.get("Name")}

        return _resp(
            200,
            {
                "username": username,
                "enabled": bool(u.get("Enabled")),
                "status": u.get("UserStatus"),
                "attributes": attrs_map,
            },
        )

    except cognito.exceptions.UserNotFoundException:
        return _resp(404, {"error": "user_not_found"})
    except cognito.exceptions.InvalidParameterException as e:
        return _resp(400, {"error": "invalid_parameter", "detail": str(e)})
    except cognito.exceptions.InvalidPasswordException as e:
        return _resp(400, {"error": "invalid_password", "detail": str(e)})
    except cognito.exceptions.TooManyRequestsException as e:
        return _resp(429, {"error": "too_many_requests", "detail": str(e)})
    except Exception as e:
        log.exception("admin_update_user failed")
        return _resp(500, {"error": "internal_error", "detail": str(e)})
