from __future__ import annotations

import logging
import os
from pathlib import Path

import typer
from rich.console import Console

from fenrir.core.authenticator import (
    TOKEN_CACHE_DIR,
    AuthFlow,
    AzureAuthenticator,
    Credentials,
)

log = logging.getLogger(__name__)
console = Console(stderr=True)
err_console = Console(stderr=True)


def _resolve_creds(
    username: str | None,
    password: str | None,
    password_file: Path | None,
    tenant: str | None,
    client_id: str | None,
    scopes: str | None,
    auth_flow: str | None,
    token_cache: Path | None,
) -> Credentials:
    u = username or os.environ.get("AZAUTH_USERNAME")
    p = password or os.environ.get("AZAUTH_PASSWORD")
    t = tenant or os.environ.get("AZAUTH_TENANT")
    c = client_id or os.environ.get("AZAUTH_CLIENT_ID")
    s = scopes or os.environ.get("AZAUTH_SCOPES", "https://graph.microsoft.com/.default")
    f = auth_flow or os.environ.get("AZAUTH_AUTH_FLOW", "device-code")
    tc = token_cache or (TOKEN_CACHE_DIR / "token_cache.bin")

    if password_file:
        try:
            p = password_file.read_text().strip()
        except Exception as e:
            err_console.print(f"[red]Error reading password file:[/red] {e}")
            raise typer.Exit(code=2)

    if f not in ("device-code", "interactive", "ropc"):
        err_console.print(
            f"[red]Invalid auth-flow:[/red] {f} — use device-code, interactive, or ropc"
        )
        raise typer.Exit(code=2)

    return Credentials(
        username=u,
        password=p,
        tenant=t,
        client_id=c,
        scopes=[s.strip() for s in s.split(",") if s.strip()],
        auth_flow=f,  # type: ignore
        token_cache_path=tc,
    )


def login(
    ctx: typer.Context,
    username: str = typer.Option(
        None, "--username", "-u", help="Azure username / email", show_envvar="AZAUTH_USERNAME",
    ),
    password: str = typer.Option(
        None, "--password", "-p",
        help="Password (only needed for --auth-flow ropc)",
        show_envvar="AZAUTH_PASSWORD",
    ),
    password_file: Path = typer.Option(
        None, "--password-file", "--pf",
        help="Read password from file (only for ropc flow)",
        exists=True, dir_okay=False,
    ),
    tenant: str = typer.Option(
        None, "--tenant", "-t", help="Tenant ID or domain name",
        show_envvar="AZAUTH_TENANT",
    ),
    client_id: str = typer.Option(
        None, "--client-id", help="Azure app registration client ID",
        show_envvar="AZAUTH_CLIENT_ID",
    ),
    scopes: str = typer.Option(
        None, "--scopes", help="Comma-separated scopes (default: https://graph.microsoft.com/.default)",
        show_envvar="AZAUTH_SCOPES",
    ),
    auth_flow: str = typer.Option(
        None, "--auth-flow",
        help="Auth flow: device-code (default), interactive (needs --client-id), ropc",
        show_envvar="AZAUTH_AUTH_FLOW",
    ),
    token_cache: Path = typer.Option(
        None, "--token-cache",
        help="Path to token cache file",
        file_okay=True, dir_okay=False,
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose logging"),
):
    """Authenticate to Azure using OAuth 2.0.

    Defaults to device code flow (prints a code, open browser). Use
    --auth-flow interactive for local browser popup (needs your own
    app registration with http://localhost redirect URI).
    """
    from fenrir.core.logging_util import configure_logging
    if verbose or ctx.obj.get("verbose"):
        configure_logging(verbose=True)

    creds = _resolve_creds(
        username=username,
        password=password,
        password_file=password_file,
        tenant=tenant,
        client_id=client_id,
        scopes=scopes,
        auth_flow=auth_flow,
        token_cache=token_cache,
    )

    if creds.auth_flow == "ropc" and not creds.password:
        err_console.print("[red]Error:[/red] --password required for ropc flow")
        raise typer.Exit(code=2)

    authenticator = AzureAuthenticator(creds)
    result = authenticator.authenticate()

    if result.success:
        console.print(
            f"[green]Authenticated as[/green] [bold]{result.username}[/bold] "
            f"(tenant: {result.tenant_id})"
        )
        ctx.obj["token"] = result.token
        return result.token
    else:
        err_console.print(f"[red]Authentication failed:[/red] {result.error}")
        raise typer.Exit(code=3)
