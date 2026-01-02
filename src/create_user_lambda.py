import base64
import json
import logging
import os
from typing import Any, Dict, List

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


def _is_admin(event: Dict[str, Any]) -> bool:
    return ADMIN_GROUP in _extract_groups(event)


def lambda_handler(event, context):
    """
    body:
      email: str
      tempPassword: str (optional; if not provided, Cognito generates it)

    Must be called behind API Gateway HTTP API + JWT authorizer.
    """
    rc = event.get("requestContext") or {}
    claims = (((rc.get("authorizer") or {}).get("jwt") or {}).get("claims")) or {}
    log.info("CLAIMS=%s", json.dumps(claims))

    if not _is_admin(event):
        return _resp(403, {"error": "forbidden", "detail": "admin_only"})

    data = _parse_body(event)
    email = data.get("email")
    if not email:
        return _resp(400, {"error": "missing_email"})

    params = {
        "UserPoolId": USER_POOL_ID,
        "Username": email,
        "UserAttributes": [
            {"Name": "email", "Value": email},
            {"Name": "email_verified", "Value": "true"},
        ],
        "DesiredDeliveryMediums": ["EMAIL"],
    }

    temp_password = data.get("tempPassword")
    if temp_password:
        params["TemporaryPassword"] = temp_password

    try:
        resp = cognito.admin_create_user(**params)
        status = resp["User"]["UserStatus"]
        return _resp(200, {"email": email, "status": status})
    except cognito.exceptions.UsernameExistsException:
        return _resp(409, {"error": "user_already_exists"})
    except cognito.exceptions.InvalidPasswordException as e:
        return _resp(400, {"error": "invalid_password", "detail": str(e)})
    except cognito.exceptions.InvalidParameterException as e:
        return _resp(400, {"error": "invalid_parameter", "detail": str(e)})
    except cognito.exceptions.TooManyRequestsException as e:
        return _resp(429, {"error": "too_many_requests", "detail": str(e)})
    except Exception as e:
        return _resp(500, {"error": "internal_error", "detail": str(e)})
