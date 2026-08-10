from __future__ import annotations

from datetime import datetime, timezone

import typer
from rich.console import Console
from rich.table import Table

from fenrir.core.authenticator import AzureAuthenticator, Credentials

console = Console(stderr=True)


def status(
    ctx: typer.Context,
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Show token details",
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Output as JSON",
    ),
    token_cache: str = typer.Option(
        None, "--token-cache", help="Path to token cache file",
    ),
):
    """Show current authentication status."""
    from fenrir.core.logging_util import configure_logging
    if verbose or ctx.obj.get("verbose"):
        configure_logging(verbose=True)

    creds = Credentials()
    if token_cache:
        creds.token_cache_path = __import__("pathlib").Path(token_cache)

    authenticator = AzureAuthenticator(creds)
    accounts = authenticator.list_accounts()
    token_result = authenticator.get_token()

    if json_output:
        import json as _json
        data = {
            "authenticated": token_result.success,
            "username": token_result.username,
            "tenant_id": token_result.tenant_id,
            "accounts": [
                {
                    "username": a.get("username"),
                    "tenant_id": a.get("tenant_id"),
                    "home_account_id": a.get("home_account_id"),
                }
                for a in accounts
            ],
        }
        console.print(_json.dumps(data, indent=2))
        return

    if not accounts:
        console.print("[yellow]No cached accounts found[/yellow]")
        console.print("Run [bold]fenrir login[/bold] to sign in.")
        return

    table = Table(title="Cached Accounts")
    table.add_column("Username", style="cyan")
    table.add_column("Tenant ID")
    table.add_column("Home Account ID")

    for account in accounts:
        table.add_row(
            account.get("username", "?"),
            account.get("tenant_id", "?"),
            account.get("home_account_id", "?"),
        )
    console.print(table)

    if token_result.success:
        expires_on = token_result.token.get("expires_on") if token_result.token else None
        expires_str = ""
        if expires_on:
            try:
                dt = datetime.fromtimestamp(int(expires_on), tz=timezone.utc)
                expires_str = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            except Exception:
                expires_str = str(expires_on)

        console.print(
            f"\n[green]Authenticated as[/green] {token_result.username} "
            f"(expires: {expires_str})"
        )

        if verbose and token_result.token:
            console.print("\n[yellow]Token details:[/yellow]")
            access = token_result.token.get("access_token", "")
            console.print(f"  Access token: {access[:80]}...")
            refresh = token_result.token.get("refresh_token", "")
            if refresh:
                console.print(f"  Refresh token: {refresh[:80]}...")
            console.print(f"  Expires: {expires_str}")
    else:
        console.print(f"\n[yellow]Token expired or unavailable[/yellow]")
