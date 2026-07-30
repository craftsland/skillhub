#!/usr/bin/env python3
"""Minimal loopback-only GitLab OAuth provider for browser E2E tests."""

from __future__ import annotations

import argparse
import json
import secrets
import threading
import time
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse


class OAuthState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.code_subjects: dict[str, str] = {}
        self.token_subjects: dict[str, str] = {}

    def issue_code(self, subject: str) -> str:
        code = secrets.token_urlsafe(24)
        with self.lock:
            self.code_subjects[code] = subject
        return code

    def exchange(self, code: str) -> str | None:
        with self.lock:
            subject = self.code_subjects.pop(code, None)
            if subject is None:
                return None
            token = secrets.token_urlsafe(24)
            self.token_subjects[token] = subject
            return token

    def subject_for_token(self, token: str) -> str | None:
        with self.lock:
            return self.token_subjects.get(token)


STATE = OAuthState()


class OAuthHandler(BaseHTTPRequestHandler):
    server_version = "SkillHubOAuthMock/1.0"

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self.send_json(HTTPStatus.OK, {"status": "UP"})
            return
        if parsed.path == "/oauth/authorize":
            self.authorize(parse_qs(parsed.query))
            return
        if parsed.path == "/api/v4/user":
            self.user_info()
            return
        if parsed.path == "/api/v4/user/emails":
            self.user_emails()
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802
        if urlparse(self.path).path != "/oauth/token":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        length = int(self.headers.get("Content-Length", "0"))
        form = parse_qs(
            self.rfile.read(length).decode("utf-8"),
            keep_blank_values=True,
        )
        code = first(form, "code")
        token = STATE.exchange(code)
        if token is None:
            self.send_json(
                HTTPStatus.BAD_REQUEST,
                {
                    "error": "invalid_grant",
                    "error_description": "Unknown authorization code",
                },
            )
            return
        self.send_json(
            HTTPStatus.OK,
            {
                "access_token": token,
                "token_type": "Bearer",
                "expires_in": 300,
                "created_at": int(time.time()),
            },
        )

    def authorize(self, query: dict[str, list[str]]) -> None:
        redirect_uri = first(query, "redirect_uri")
        state = first(query, "state")
        if not safe_callback(redirect_uri):
            self.send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "invalid_redirect_uri"},
            )
            return
        subject = self.subject_cookie()
        created_subject = subject is None
        if subject is None:
            subject = str(10**11 + secrets.randbelow(9 * 10**11))
        code = STATE.issue_code(subject)
        parsed = urlparse(redirect_uri)
        callback_query = parse_qs(
            parsed.query,
            keep_blank_values=True,
        )
        callback_query["code"] = [code]
        callback_query["state"] = [state]
        location = urlunparse(
            parsed._replace(query=urlencode(callback_query, doseq=True))
        )
        self.send_response(HTTPStatus.FOUND)
        if created_subject:
            self.send_header(
                "Set-Cookie",
                "skillhub_mock_subject="
                + subject
                + "; Path=/; HttpOnly; SameSite=Lax",
            )
        self.send_header("Location", location)
        self.end_headers()

    def user_info(self) -> None:
        subject = self.authenticated_subject()
        if subject is None:
            return
        self.send_json(
            HTTPStatus.OK,
            {
                "id": int(subject),
                "username": "mock_gitlab_" + subject,
                "name": "Mock GitLab User",
                "email": subject + "@gitlab.example.test",
                "confirmed_at": "2026-07-31T00:00:00Z",
                "avatar_url": None,
            },
        )

    def user_emails(self) -> None:
        subject = self.authenticated_subject()
        if subject is None:
            return
        self.send_json(
            HTTPStatus.OK,
            [
                {
                    "email": subject + "@gitlab.example.test",
                    "confirmed_at": "2026-07-31T00:00:00Z",
                }
            ],
        )

    def authenticated_subject(self) -> str | None:
        authorization = self.headers.get("Authorization", "")
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            self.send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "invalid_token"},
            )
            return None
        subject = STATE.subject_for_token(token)
        if subject is None:
            self.send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "invalid_token"},
            )
        return subject

    def subject_cookie(self) -> str | None:
        cookie = SimpleCookie()
        cookie.load(self.headers.get("Cookie", ""))
        morsel = cookie.get("skillhub_mock_subject")
        if morsel is None or not morsel.value.isdecimal():
            return None
        return morsel.value

    def send_json(
        self,
        status: HTTPStatus,
        body: object,
    ) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(
        self,
        format_string: str,
        *args: object,
    ) -> None:
        del format_string, args


def first(values: dict[str, list[str]], key: str) -> str:
    candidates = values.get(key)
    return candidates[0] if candidates else ""


def safe_callback(value: str) -> bool:
    parsed = urlparse(value)
    return (
        parsed.scheme == "http"
        and parsed.hostname in {"127.0.0.1", "localhost"}
        and parsed.path == "/login/oauth2/code/gitlab"
        and parsed.username is None
        and parsed.password is None
        and parsed.fragment == ""
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    server = ThreadingHTTPServer(
        ("127.0.0.1", args.port),
        OAuthHandler,
    )
    print(f"LISTENING_PORT={server.server_port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
