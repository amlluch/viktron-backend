import base64
import json
import os
from typing import Any, Dict

import boto3

cognito = boto3.client("cognito-idp")
USER_POOL_ID = os.environ["USER_POOL_ID"]


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


def lambda_handler(event, context):
    """
    body:
      email: str
      tempPassword: str (opcional; si no lo pasas, Cognito la genera)
    """
    data = _parse_body(event)
    email = data.get("email")
    if not email:
        return _resp(400, {"error": "missing_email"})

    params = {
        "UserPoolId": USER_POOL_ID,
        "Username": email,
        "UserAttributes": [{"Name": "email", "Value": email}],
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
    except Exception as e:
        return _resp(500, {"error": "internal_error", "detail": str(e)})
