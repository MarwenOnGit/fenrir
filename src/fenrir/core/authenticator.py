from __future__ import annotations

import json
import logging
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import msal

log = logging.getLogger(__name__)

DEFAULT_SCOPES = ["https://graph.microsoft.com/.default"]
DEFAULT_AUTHORITY = "https://login.microsoftonline.com/common"
TOKEN_CACHE_DIR = Path.home() / ".config" / "fenrir"
TOKEN_CACHE_FILE = TOKEN_CACHE_DIR / "token_cache.bin"

AuthFlow = Literal["device-code", "interactive", "ropc"]


@dataclass
class AuthResult:
    success: bool
    token: dict | None = None
    username: str | None = None
    tenant_id: str | None = None
    error: str | None = None
    error_code: str | None = None


@dataclass
class Credentials:
    username: str | None = None
    password: str | None = None
    tenant: str | None = None
    client_id: str | None = None
    scopes: list[str] = field(default_factory=lambda: DEFAULT_SCOPES.copy())
    auth_flow: AuthFlow = "device-code"
    token_cache_path: Path = TOKEN_CACHE_FILE


class AzureAuthenticator:
    def __init__(self, creds: Credentials):
        self.creds = creds
        self._token_cache: msal.SerializableTokenCache | None = None
        self._app: msal.PublicClientApplication | None = None
        self._cached_account: dict | None = None

    @property
    def token_cache(self) -> msal.SerializableTokenCache:
        if self._token_cache is None:
            self._token_cache = msal.SerializableTokenCache()
            cache_path = self.creds.token_cache_path
            if cache_path.exists():
                try:
                    self._token_cache.deserialize(cache_path.read_text())
                    log.debug("Loaded token cache from %s", cache_path)
                except Exception:
                    log.warning("Failed to read token cache, starting fresh")
        return self._token_cache

    def save_token_cache(self) -> None:
        if not self._token_cache or not self._token_cache.has_state_changed:
            return
        cache_path = self.creds.token_cache_path
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(self._token_cache.serialize())
        log.debug("Saved token cache to %s", cache_path)

    @property
    def app(self) -> msal.PublicClientApplication:
        if self._app is None:
            authority = f"https://login.microsoftonline.com/{self.creds.tenant}" if self.creds.tenant else DEFAULT_AUTHORITY
            self._app = msal.PublicClientApplication(
                client_id=self.creds.client_id or self._default_client_id(),
                authority=authority,
                token_cache=self.token_cache,
            )
        return self._app

    @staticmethod
    def _default_client_id() -> str:
        return os.environ.get("AZAUTH_CLIENT_ID", "04b07795-8ddb-461a-bbee-02f9e1bf7b46")

    def _try_silent(self) -> AuthResult:
        accounts = self.app.get_accounts()
        if not accounts:
            return AuthResult(success=False, error="No cached accounts")

        for account in accounts:
            result = self.app.acquire_token_silent(
                scopes=self.creds.scopes, account=account
            )
            if result and "access_token" in result:
                self._cached_account = account
                self.save_token_cache()
                return AuthResult(
                    success=True,
                    token=result,
                    username=account.get("username"),
                    tenant_id=account.get("tenant_id"),
                )
        return AuthResult(success=False, error="No valid cached token found")

    def authenticate(self) -> AuthResult:
        log.debug("Starting authentication, flow=%s", self.creds.auth_flow)

        cached = self._try_silent()
        if cached.success:
            log.info("Reused cached token for %s", cached.username)
            return cached

        flow = self.creds.auth_flow
        if flow == "ropc":
            if not self.creds.username or not self.creds.password:
                return AuthResult(
                    success=False,
                    error="--username and --password required for ROPC flow",
                )
            return self._ropc_flow()
        if flow == "interactive":
            return self._interactive_flow()

        return self._device_code_flow()

    def _ropc_flow(self) -> AuthResult:
        log.debug("Attempting ROPC flow for %s", self.creds.username)
        if not self.creds.username or not self.creds.password:
            return AuthResult(
                success=False,
                error="Username and password required for ROPC flow",
            )
        try:
            result = self.app.acquire_token_by_username_password(
                username=self.creds.username,
                password=self.creds.password,
                scopes=self.creds.scopes,
            )
        except Exception as e:
            return AuthResult(success=False, error=str(e))

        return self._process_msal_result(result)

    def _device_code_flow(self) -> AuthResult:
        log.debug("Starting device code flow")
        try:
            flow = self.app.initiate_device_flow(scopes=self.creds.scopes)
            if "user_code" not in flow:
                return AuthResult(
                    success=False,
                    error=flow.get("error_description", "Failed to start device flow"),
                )

            print(file=sys.stderr)
            from rich.markdown import Markdown
            from rich.console import Console
            console = Console(stderr=True)
            msg = (
                f"To sign in, open:\n\n"
                f"  **{flow['verification_uri']}**\n\n"
                f"and enter the code:\n\n"
                f"  **{flow['user_code']}**\n\n"
                f"This device code will expire in {flow.get('expires_in', 900)} seconds."
            )
            console.print(Markdown(msg))
            print(file=sys.stderr)

            result = self.app.acquire_token_by_device_flow(flow)
            return self._process_msal_result(result)
        except Exception as e:
            return AuthResult(success=False, error=str(e))

    def _interactive_flow(self) -> AuthResult:
        log.debug("Starting interactive browser flow")
        try:
            result = self.app.acquire_token_interactive(scopes=self.creds.scopes)
            return self._process_msal_result(result)
        except Exception as e:
            return AuthResult(success=False, error=str(e))

    def _process_msal_result(self, result: dict) -> AuthResult:
        if "access_token" in result:
            username = result.get("id_token_claims", {}).get("preferred_username")
            if not username and result.get("account"):
                username = result["account"].get("username")
            tenant_id = result.get("id_token_claims", {}).get("tid")
            self.save_token_cache()
            return AuthResult(
                success=True,
                token=result,
                username=username,
                tenant_id=tenant_id,
            )

        error = result.get("error_description", result.get("error", "Unknown error"))
        error_code = result.get("error")
        if not error_code and result.get("error_description"):
            for code in ("50076", "50079", "50097", "50158", "65001"):
                if code in result.get("error_description", ""):
                    error_code = code
                    break
        description = result.get("error_description", error)
        return AuthResult(
            success=False,
            error=description,
            error_code=error_code,
        )

    def logout(self) -> None:
        accounts = self.app.get_accounts()
        for account in accounts:
            self.app.remove_account(account)
        cache_path = self.creds.token_cache_path
        if cache_path.exists():
            cache_path.unlink()
        self._cached_account = None
        log.info("Removed all cached accounts")

    def get_token(self) -> AuthResult:
        cached = self._try_silent()
        if cached.success:
            return cached
        return self.authenticate()

    def get_token_for_scopes(self, scopes: list[str]) -> AuthResult:
        accounts = self.app.get_accounts()
        if accounts:
            for account in accounts:
                result = self.app.acquire_token_silent(scopes=scopes, account=account)
                if result and "access_token" in result:
                    self._cached_account = account
                    self.save_token_cache()
                    return AuthResult(
                        success=True,
                        token=result,
                        username=account.get("username"),
                        tenant_id=account.get("tenant_id"),
                    )
        log.info("No cached token for scopes %s — starting device code flow", scopes)
        saved = self.creds.scopes
        self.creds.scopes = scopes
        try:
            result = self._device_code_flow()
            return result
        finally:
            self.creds.scopes = saved

    def list_accounts(self) -> list[dict]:
        return self.app.get_accounts()
