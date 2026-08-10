from pathlib import Path

import typer

from fenrir.core.logging_util import configure_logging
from fenrir.commands import login, logout, status, token
from fenrir.commands import enumerate as enumerate_cmd_mod
from fenrir.commands import exploit as exploit_mod
from fenrir.commands import post_exploit as post_exploit_mod

app = typer.Typer(
    name="fenrir",
    help="Azure CLI authenticator — email/password login with automatic MFA fallback.",
    no_args_is_help=True,
)

app.command(name="login")(login.login)
app.command(name="logout")(logout.logout)
app.command(name="status")(status.status)
app.command(name="token")(token.token_cmd)
app.command(name="enumerate", help="Enumerate all accessible Azure assets.")(enumerate_cmd_mod.enumerate_cmd)
app.command(
    name="exploit",
    help="Discover Azure resources, check RBAC, and extract managed identity tokens.",
)(exploit_mod.exploit)
app.command(
    name="post-exploit",
    help="Enumerate what a compromised managed identity controls across the whole tenant.",
)(post_exploit_mod.post_exploit)


def _version_callback(value: bool) -> None:
    if value:
        from importlib.metadata import version
        try:
            ver = version("fenrir")
        except Exception:
            ver = "0.1.0 (dev)"
        typer.echo(f"fenrir {ver}")
        raise typer.Exit()


@app.callback()
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False, "--version", "-V", help="Show version and exit", callback=_version_callback,
        is_eager=True,
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose logging"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress non-data output"),
):
    configure_logging(verbose=verbose, quiet=quiet)

    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["quiet"] = quiet


if __name__ == "__main__":
    app()
