import base64
import json
import os
from typing import Any, Dict

import boto3

cognito = boto3.client("cognito-idp")

USER_POOL_ID = os.environ["USER_POOL_ID"]
CLIENT_ID = os.environ["CLIENT_ID"]


def _parse_body(event: Dict[str, Any]) -> Dict[str, Any]:
    body = event.get("body")
    if not body:
        return {}
    if event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode("utf-8")
    if isinstance(body, str):
        return json.loads(body)
    return body  # por si invocas desde consola con dict


def _resp(status: int, payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "statusCode": status,
        "headers": {"content-type": "application/json"},
        "body": json.dumps(payload),
    }


def lambda_handler(event, context):
    """
    body:
      action: "login" | "new_password" | "refresh"
      email, password, newPassword, session, refreshToken
    """
    data = _parse_body(event)
    action = data.get("action")

    try:
        if action == "login":
            return _login(data)
        if action == "new_password":
            return _new_password(data)
        if action == "refresh":
            return _refresh(data)

        return _resp(400, {"error": "unknown_action"})
    except cognito.exceptions.NotAuthorizedException:
        return _resp(401, {"error": "not_authorized"})
    except cognito.exceptions.UserNotFoundException:
        return _resp(404, {"error": "user_not_found"})
    except Exception as e:
        return _resp(500, {"error": "internal_error", "detail": str(e)})


def _login(data: Dict[str, Any]) -> Dict[str, Any]:
    email = data["email"]
    password = data["password"]

    resp = cognito.admin_initiate_auth(
        UserPoolId=USER_POOL_ID,
        ClientId=CLIENT_ID,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={
            "USERNAME": email,
            "PASSWORD": password,
        },
    )

    if resp.get("ChallengeName") == "NEW_PASSWORD_REQUIRED":
        return _resp(
            200,
            {
                "challenge": "NEW_PASSWORD_REQUIRED",
                "session": resp["Session"],
                "challengeParameters": resp.get("ChallengeParameters", {}),
            },
        )

    auth = resp["AuthenticationResult"]
    return _resp(
        200,
        {
            "accessToken": auth["AccessToken"],
            "idToken": auth["IdToken"],
            "refreshToken": auth.get("RefreshToken"),
            "expiresIn": auth["ExpiresIn"],
            "tokenType": auth["TokenType"],
        },
    )


def _new_password(data: Dict[str, Any]) -> Dict[str, Any]:
    email = data["email"]
    new_password = data["newPassword"]
    session = data["session"]

    resp = cognito.admin_respond_to_auth_challenge(
        UserPoolId=USER_POOL_ID,
        ClientId=CLIENT_ID,
        ChallengeName="NEW_PASSWORD_REQUIRED",
        Session=session,
        ChallengeResponses={
            "USERNAME": email,
            "NEW_PASSWORD": new_password,
        },
    )

    auth = resp["AuthenticationResult"]
    return _resp(
        200,
        {
            "accessToken": auth["AccessToken"],
            "idToken": auth["IdToken"],
            "refreshToken": auth.get("RefreshToken"),
            "expiresIn": auth["ExpiresIn"],
            "tokenType": auth["TokenType"],
        },
    )


def _refresh(data: Dict[str, Any]) -> Dict[str, Any]:
    refresh_token = data["refreshToken"]

    resp = cognito.admin_initiate_auth(
        UserPoolId=USER_POOL_ID,
        ClientId=CLIENT_ID,
        AuthFlow="REFRESH_TOKEN_AUTH",
        AuthParameters={"REFRESH_TOKEN": refresh_token},
    )

    auth = resp["AuthenticationResult"]
    return _resp(
        200,
        {
            "accessToken": auth["AccessToken"],
            "idToken": auth["IdToken"],
            "expiresIn": auth["ExpiresIn"],
            "tokenType": auth["TokenType"],
        },
    )
