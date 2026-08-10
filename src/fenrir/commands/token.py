from __future__ import annotations

import sys

import typer
from rich.console import Console

from fenrir.core.authenticator import AzureAuthenticator, Credentials

err_console = Console(stderr=True)


def token_cmd(
    ctx: typer.Context,
    raw: bool = typer.Option(
        False, "--raw", help="Print only the access token (stdout, for piping)",
    ),
    username: str = typer.Option(None, "--username", "-u"),
    tenant: str = typer.Option(None, "--tenant", "-t"),
    client_id: str = typer.Option(None, "--client-id"),
    scopes: str = typer.Option(
        None, "--scopes",
        help="Comma-separated scopes (default: uses scopes from login)",
        show_envvar="AZAUTH_SCOPES",
    ),
    token_cache: str = typer.Option(None, "--token-cache"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose logging"),
):
    """Retrieve an access token (refreshing if needed).

    Uses the cached refresh token to silently request tokens for any scope
    the original login consented to — no re-authentication required.
    """
    from fenrir.core.logging_util import configure_logging
    if verbose or ctx.obj.get("verbose"):
        configure_logging(verbose=True)

    import os
    from fenrir.core.authenticator import Credentials as C
    from pathlib import Path

    resolved_scopes = (
        scopes or os.environ.get("AZAUTH_SCOPES", "https://graph.microsoft.com/.default")
    )

    creds = C(
        username=username or os.environ.get("AZAUTH_USERNAME"),
        tenant=tenant or os.environ.get("AZAUTH_TENANT"),
        client_id=client_id or os.environ.get("AZAUTH_CLIENT_ID"),
        scopes=[s.strip() for s in resolved_scopes.split(",")] if resolved_scopes else None,
    )
    if token_cache:
        creds.token_cache_path = Path(token_cache)

    authenticator = AzureAuthenticator(creds)
    result = authenticator.get_token()

    if not result.success:
        err_console.print(f"[red]Failed to get token:[/red] {result.error}")
        raise typer.Exit(code=3)

    token = result.token.get("access_token", "") if result.token else ""

    if raw:
        sys.stdout.write(token)
        if not token.endswith("\n"):
            sys.stdout.write("\n")
        return

    from rich import print_json
    import json
    output = {
        "access_token": token[:80] + "..." if len(token) > 80 else token,
        "username": result.username,
        "tenant_id": result.tenant_id,
        "expires_on": result.token.get("expires_on") if result.token else None,
    }
    print_json(data=output)
