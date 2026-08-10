from __future__ import annotations

import json
import logging
import time

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from fenrir.core.authenticator import AzureAuthenticator, Credentials
from fenrir.core.enumerate.collector import EnumerateCollector
from fenrir.core.enumerate.models import EnumerationResult
from fenrir.core.enumerate.verdict import (
    ReadinessVerdict,
    VerdictStatus,
    assess_exploit_readiness,
)
from fenrir.state import from_enumeration_result, save_state

log = logging.getLogger(__name__)
console = Console(stderr=True)
out_console = Console()


def _short_type(resource_type: str) -> str:
    return resource_type.rsplit("/", 1)[-1] if resource_type else "?"


def _build_tree(result: EnumerationResult) -> Tree:
    me = result.me or {}
    upn = me.get("userPrincipalName", me.get("displayName", "Unknown"))
    tree = Tree(f"[bold cyan]{upn}[/bold cyan]", guide_style="bright_black")

    if result.errors:
        err_node = tree.add("[bold red]Errors[/bold red]")
        for e in result.errors:
            err_node.add(f"[red]{e}[/red]")

    tenant = tree.add(f"[bold]Tenant[/bold]  {me.get('tenantId', '?')}")

    domains = result.domains
    if domains:
        d_node = tenant.add(f"[bold]Domains[/bold] ({len(domains)})")
        for d in domains:
            verified = "[green]verified[/green]" if d.is_verified else "[yellow]unverified[/yellow]"
            d_node.add(f"{d.id}  ({verified})")

    roles = result.directory_roles
    if roles:
        r_node = tenant.add(f"[bold]Directory Roles[/bold] ({len(roles)})")
        seen = set()
        for ra in roles:
            name = ra.role.display_name
            if name not in seen:
                seen.add(name)
                r_node.add(f"{name}")

    pim = result.pim_roles
    if pim:
        p_node = tenant.add(f"[bold]PIM Roles[/bold] ({len(pim)})")
        for p in pim:
            p_node.add(f"{p.role_name}  [{p.status}]")

    groups = result.groups
    if groups:
        g_node = tenant.add(f"[bold]Groups[/bold] ({len(groups)})")
        for g in groups:
            g_node.add(f"{g.display_name}  ({g.group_type})")

    owned_apps = result.owned_applications
    if owned_apps:
        a_node = tenant.add(f"[bold]Owned Applications[/bold] ({len(owned_apps)})")
        for app in owned_apps:
            creds = []
            if app.password_credentials:
                creds.append(f"{app.password_credentials}pwd")
            if app.key_credentials:
                creds.append(f"{app.key_credentials}key")
            suffix = f"  [yellow]({', '.join(creds)})[/yellow]" if creds else ""
            a_node.add(f"{app.display_name}{suffix}")

    owned_sps = result.owned_service_principals
    if owned_sps:
        sp_node = tenant.add(f"[bold]Owned Service Principals[/bold] ({len(owned_sps)})")
        for sp in owned_sps:
            creds = []
            if sp.password_credentials:
                creds.append(f"{sp.password_credentials}pwd")
            if sp.key_credentials:
                creds.append(f"{sp.key_credentials}key")
            suffix = f"  [yellow]({', '.join(creds)})[/yellow]" if creds else ""
            sp_node.add(f"{sp.display_name}{suffix}")

    devices = result.managed_devices
    if devices:
        d_node = tenant.add(f"[bold]Managed Devices[/bold] ({len(devices)})")
        for dev in devices:
            d_node.add(f"{dev.display_name}  ({dev.operating_system or '?'})")

    subs = result.subscriptions
    if subs:
        sub_node = tree.add(f"[bold green]Subscriptions[/bold green] ({len(subs)})")
        for sub in subs:
            roles_str = ", ".join(sub.roles) if sub.roles else "[dim]no direct role[/dim]"
            s = sub_node.add(
                f"[bold]{sub.display_name}[/bold]  ({sub.state}) — {roles_str}"
            )
            if not sub.resource_groups:
                s.add("[dim]no resource-group access found[/dim]")
            for rg in sub.resource_groups:
                rg_label = f"[bold yellow]{rg.name}[/bold yellow]  ({rg.location})"
                if rg.roles:
                    rg_label += f"  \\[roles: {', '.join(rg.roles)}]"
                rg_node = s.add(rg_label)
                if not rg.resources:
                    rg_node.add("[dim]no resources listed[/dim]")
                for res in rg.resources:
                    mi = ""
                    if res.has_managed_identity:
                        ident = f" ({res.identity_type})" if res.identity_type else ""
                        mi = f"  [bold magenta]MI{ident}[/bold magenta]"
                    res_roles = f"  \\[{', '.join(res.roles)}]" if res.roles else ""
                    rg_node.add(f"{res.name}  ({_short_type(res.type)}){res_roles}{mi}")

    mg = result.management_groups
    if mg:
        mg_node = tree.add(f"[bold]Management Groups[/bold] ({len(mg)})")
        for m in mg:
            mg_node.add(m.display_name)

    return tree


def _opportunity_lines(verdict: ReadinessVerdict) -> list[str]:
    lines: list[str] = []
    if not verdict.opportunities:
        return lines
    lines.append("")
    lines.append("[bold]Exploit opportunities found:[/bold]")
    for opp in verdict.opportunities:
        lines.append(f"  [bold cyan]{opp['summary']}[/bold cyan]")
        lines.append(f"      [dim]{opp['detail']}[/dim]")
    return lines


def _verdict_panel(verdict: ReadinessVerdict) -> Panel:
    if verdict.status == VerdictStatus.READY:
        title = "[bold green]READY — MI impersonation possible, proceed to the exploit phase[/bold green]"
        border = "green"
        lines = [
            "[green]You hold exploit-relevant roles at resource-group scope:[/green]",
        ]
        for role, scopes in sorted(verdict.interesting_roles.items()):
            lines.append(f"  [bold]{role}[/bold]  →  {', '.join(scopes)}")
        if verdict.notable_roles:
            lines.append("")
            lines.append("[green]Other notable access (non-MI data/credential roles):[/green]")
            for role, scopes in sorted(verdict.notable_roles.items()):
                lines.append(f"  [bold]{role}[/bold]  →  {', '.join(scopes)}")
        lines.append("")
        lines.append("[bold]Managed-identity resources you can dump tokens from:[/bold]")
        for m in verdict.mi_targets:
            lines.append(f"  [cyan]{m['name']}[/cyan]  ({m['type'].rsplit('/', 1)[-1]})  in [bold]{m['resource_group']}[/bold]")
        if verdict.uai_count:
            lines.append(
                f"[yellow]{verdict.uai_count} user-assigned identit(y/ies) present — "
                f"dumped automatically when assigned to a host above.[/yellow]"
            )
        lines.extend(_opportunity_lines(verdict))
        lines.append("")
        lines.append("[bold]Next:[/bold] [cyan]fenrir exploit[/cyan]  →  [cyan]fenrir post-exploit[/cyan]")
    elif verdict.status == VerdictStatus.BLOCKED_NO_TARGETS:
        title = "[bold yellow]PAUSE — rights but no managed identity targets[/bold yellow]"
        border = "yellow"
        lines = [
            f"[yellow]{verdict.reasons[0] if verdict.reasons else 'No MI-capable resource with an identity was found.'}[/yellow]",
        ]
        for reason in verdict.reasons[1:]:
            lines.append(f"[yellow]{reason}[/yellow]")
        lines.extend(_opportunity_lines(verdict))
        lines.append(
            "[yellow]No need to run the exploit phase until a managed identity is introduced.[/yellow]"
        )
    elif verdict.status == VerdictStatus.BLOCKED_NO_RIGHTS:
        title = "[bold red]STOP — no exploitable rights[/bold red]"
        border = "red"
        lines = [
            f"[red]{verdict.reasons[0] if verdict.reasons else 'No exploit-relevant role found at any resource-group scope.'}[/red]",
            "[red]The exploit phase requires one of those roles to impersonate managed "
            "identities — there is no need to continue the attack.[/red]",
        ]
        if verdict.notable_roles:
            note = ", ".join(sorted(verdict.notable_roles))
            lines.append(
                "[yellow]Note: non-MI roles held at RG scope "
                f"({note}) — data/credential access only.[/yellow]"
            )
        if verdict.subscription_roles:
            note = "; ".join(
                f"{r} ({', '.join(s)})" for r, s in sorted(verdict.subscription_roles.items())
            )
            lines.append(
                "[yellow]Note: interesting roles exist at subscription scope only "
                f"({note}) — the exploit phase only checks RG-scope assignments.[/yellow]"
            )
        lines.extend(_opportunity_lines(verdict))
    else:
        title = "[bold yellow]UNVERIFIED — RG-level access not enumerated[/bold yellow]"
        border = "yellow"
        lines = [
            "[yellow]Resource groups were not enumerated (--no-resources), so RG-level "
            "role assignments are unknown.[/yellow]",
            "[yellow]Re-run [bold]fenrir enumerate[/bold] without --no-resources to "
            "assess exploit readiness.[/yellow]",
        ]

    return Panel("\n".join(lines), title=title, border_style=border)


def _build_json(result: EnumerationResult, verdict: ReadinessVerdict) -> dict:
    return {
        "me": result.me,
        "domains": [{"id": d.id, "verified": d.is_verified, "default": d.is_default} for d in result.domains],
        "directory_roles": list({ra.role.display_name for ra in result.directory_roles}),
        "pim_roles": [{"role": p.role_name, "status": p.status} for p in result.pim_roles],
        "groups": [
            {"display_name": g.display_name, "type": g.group_type}
            for g in result.groups
        ],
        "owned_applications": [
            {"display_name": a.display_name, "app_id": a.app_id, "password_creds": a.password_credentials, "key_creds": a.key_credentials}
            for a in result.owned_applications
        ],
        "owned_service_principals": [
            {"display_name": sp.display_name, "app_id": sp.app_id, "password_creds": sp.password_credentials, "key_creds": sp.key_credentials}
            for sp in result.owned_service_principals
        ],
        "managed_devices": [
            {"display_name": d.display_name, "os": d.operating_system, "compliant": d.is_compliant}
            for d in result.managed_devices
        ],
        "subscriptions": [
            {
                "display_name": s.display_name,
                "subscription_id": s.subscription_id,
                "state": s.state,
                "roles": s.roles,
                "resource_groups": [
                    {
                        "name": rg.name,
                        "location": rg.location,
                        "roles": rg.roles,
                        "resources": [
                            {
                                "name": r.name,
                                "type": r.type,
                                "roles": r.roles,
                                "has_managed_identity": r.has_managed_identity,
                                "identity_type": r.identity_type,
                            }
                            for r in rg.resources
                        ],
                    }
                    for rg in s.resource_groups
                ],
            }
            for s in result.subscriptions
        ],
        "management_groups": [
            {"name": mg.name, "display_name": mg.display_name}
            for mg in result.management_groups
        ],
        "errors": result.errors,
        "verdict": verdict.to_dict(),
    }


def enumerate_cmd(
    ctx: typer.Context,
    output: str = typer.Option(
        None, "--output", "-o",
        help="Output file path (default: stdout)",
    ),
    fmt: str = typer.Option(
        "tree", "--format", "-f",
        help="Output format: tree (default), json",
    ),
    no_resources: bool = typer.Option(
        False, "--no-resources",
        help="Skip per-subscription resource enumeration (faster)",
    ),
    token_cache: str = typer.Option(None, "--token-cache"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose logging"),
):
    """Enumerate all accessible Azure assets — roles, groups, apps, subscriptions, resources.

    Pulls data from both Microsoft Graph and Azure Resource Manager to give a
    comprehensive view of what the authenticated user owns or has privileges on,
    then ends with a verdict on whether the exploit phase can proceed.
    """
    from fenrir.core.logging_util import configure_logging
    if verbose or ctx.obj.get("verbose"):
        configure_logging(verbose=True)

    if fmt not in ("tree", "json"):
        err_console = Console(stderr=True)
        err_console.print(f"[red]Invalid format:[/red] {fmt} — use tree or json")
        raise typer.Exit(code=2)

    from pathlib import Path
    creds = Credentials()
    if token_cache:
        creds.token_cache_path = Path(token_cache)

    authenticator = AzureAuthenticator(creds)
    collector = EnumerateCollector(authenticator)
    collector.result.subscriptions = []  # reset

    # Quick auth check first
    auth_result = authenticator.get_token()
    if not auth_result.success:
        console.print("[red]Not authenticated. Run[/red] fenrir login [red]first.[/red]")
        raise typer.Exit(code=3)

    from rich.progress import (
        Progress,
        SpinnerColumn,
        TextColumn,
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
    ) as progress:
        task = progress.add_task("Enumerating Azure assets...", total=None)
        collector.collect_me()
        collector.collect_domains()
        collector.collect_directory_roles()
        collector.collect_pim_roles()
        collector.collect_groups()
        collector.collect_owned_apps()
        collector.collect_owned_service_principals()
        collector.collect_managed_devices()
        collector.collect_management_groups()
        if not no_resources:
            collector.collect_subscriptions()

    result = collector.result

    if not no_resources:
        try:
            exploit_result = from_enumeration_result(result)
            if exploit_result.interesting_groups:
                principal_id = (result.me or {}).get("id")
                state_file = save_state(exploit_result, principal_id=principal_id)
                console.print(
                    f"[green]Saved exploit state to[/green] {state_file} "
                    f"(run [cyan]fenrir exploit[/cyan] to resume from here)"
                )
        except Exception as e:
            log.warning("Failed to save exploit state: %s", e)

    try:
        verdict = assess_exploit_readiness(result, resources_collected=not no_resources)
    except Exception as e:
        log.exception("Verdict assessment failed")
        verdict = ReadinessVerdict(
            status=VerdictStatus.UNVERIFIED,
            reasons=[f"Verdict assessment failed: {e}"],
        )

    if fmt == "json":
        data = _build_json(result, verdict)
        text = json.dumps(data, indent=2, default=str)
        if output:
            Path(output).write_text(text)
            console.print(f"[green]Written to[/green] {output}")
        else:
            out_console.print(text)
        return

    tree = _build_tree(result)
    panel = _verdict_panel(verdict)

    if output:
        from rich.text import Text as RichText
        from io import StringIO
        buf = StringIO()
        from rich.console import Console as RichConsole
        RichConsole(file=buf).print(tree)
        Path(output).write_text(buf.getvalue())
        console.print(f"[green]Written to[/green] {output}")
    else:
        console.print(tree)
        console.print(panel)
