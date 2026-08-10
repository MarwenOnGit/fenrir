from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from fenrir.core.authenticator import AzureAuthenticator
from fenrir.core.enumerate.models import (
    DirectoryRole,
    DirectoryRoleAssignment,
    Domain,
    EnumerationResult,
    Group,
    ManagementGroup,
    ManagedDevice,
    OwnedApplication,
    OwnedServicePrincipal,
    PimRoleAssignment,
    Resource,
    ResourceGroup,
    Subscription,
)
from fenrir.exploit.arm_enum import INTERESTING_ROLE_NAMES, RoleAssignment

log = logging.getLogger(__name__)

GRAPH_SCOPE = "https://graph.microsoft.com/.default"
ARM_SCOPE = "https://management.azure.com/.default"

GRAPH_API = "https://graph.microsoft.com/v1.0"
ARM_API = "https://management.azure.com"

MAX_WORKERS = 8


class EnumerateCollector:
    def __init__(self, authenticator: AzureAuthenticator):
        self.auth = authenticator
        self.result = EnumerationResult()
        self._role_name_cache: dict[str, str] = {}
        self._arm_access_token: str | None = None
        self._arm_token_error: str | None = None

    def _graph_headers(self) -> dict | None:
        r = self.auth.get_token_for_scopes([GRAPH_SCOPE])
        if not r.success or not r.token:
            self.result.errors.append(f"Failed to get Graph token: {r.error}")
            return None
        return {
            "Authorization": f"Bearer {r.token['access_token']}",
            "Content-Type": "application/json",
        }

    def _arm_headers(self) -> dict | None:
        token = self._arm_token()
        if not token:
            self.result.errors.append(self._arm_token_error or "Failed to get ARM token")
            return None
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

    def _arm_token(self) -> str | None:
        if self._arm_access_token:
            return self._arm_access_token
        r = self.auth.get_token_for_scopes([ARM_SCOPE])
        if not r.success or not r.token:
            self._arm_token_error = f"Failed to get ARM token: {r.error}"
            return None
        self._arm_access_token = r.token["access_token"]
        return self._arm_access_token

    def _graph_get(
        self,
        path: str,
        params: dict | None = None,
        record_errors: bool = True,
    ) -> list[dict]:
        headers = self._graph_headers()
        if headers is None:
            return []
        results = []
        url = f"{GRAPH_API}{path}"
        while url:
            try:
                resp = requests.get(url, headers=headers, params=params, timeout=30)
                params = None
                if resp.status_code == 403:
                    log.warning("Access denied: %s", url)
                    break
                if resp.status_code == 404:
                    log.debug("Not found: %s", url)
                    break
                resp.raise_for_status()
                data = resp.json()
                results.extend(data.get("value", []))
                url = data.get("@odata.nextLink")
            except requests.RequestException as e:
                if record_errors:
                    self.result.errors.append(f"Graph GET {path}: {e}")
                else:
                    log.debug("Graph GET %s failed (ignored): %s", path, e)
                break
        return results

    def _arm_get(self, path: str, api_version: str = "2021-04-01") -> list[dict] | dict | None:
        headers = self._arm_headers()
        if headers is None:
            return None
        sep = "&" if "?" in path else "?"
        url = f"{ARM_API}{path}{sep}api-version={api_version}"
        try:
            resp = requests.get(url, headers=headers, timeout=30)
            if resp.status_code == 403:
                log.warning("Access denied: %s", path)
                return None
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, list):
                return data
            if "value" in data:
                return data["value"]
            return data
        except requests.RequestException as e:
            self.result.errors.append(f"ARM GET {path}: {e}")
            return None

    def _paginate_arm(self, path: str, api_version: str) -> list[dict]:
        headers = self._arm_headers()
        if headers is None:
            return []
        results = []
        url = f"{ARM_API}{path}?api-version={api_version}"
        while url:
            try:
                resp = requests.get(url, headers=headers, timeout=30)
                if resp.status_code == 403:
                    break
                resp.raise_for_status()
                data = resp.json()
                results.extend(data.get("value", []))
                url = data.get("nextLink")
            except requests.RequestException as e:
                self.result.errors.append(f"ARM paginate {path}: {e}")
                break
        return results

    def _role_names(self, role_def_ids: list[str]) -> list[str]:
        """Resolve role definition IDs to display names (cached, deduplicated)."""
        names: list[str] = []
        for rid in role_def_ids:
            name = self._role_name_cache.get(rid)
            if name is None:
                data = self._arm_get(rid, api_version="2022-04-01")
                if isinstance(data, dict):
                    name = (
                        (data.get("properties") or {}).get("roleName")
                        or data.get("roleName")
                    )
                name = name or rid.rsplit("/", 1)[-1]
                self._role_name_cache[rid] = name
            names.append(name)
        return names

    def _role_assignments_at_scope(self, scope_id: str, principal_id: str) -> list[RoleAssignment]:
        """Return role assignments directly assigned to the principal at a scope."""
        if not principal_id:
            return []
        data = self._paginate_arm(
            f"{scope_id}/providers/Microsoft.Authorization/roleAssignments",
            "2022-04-01",
        )
        assignments: list[RoleAssignment] = []
        for ra in data:
            props = ra.get("properties", {})
            if props.get("principalId") != principal_id:
                continue
            rid = props.get("roleDefinitionId", "")
            if not rid:
                continue
            assignments.append(RoleAssignment(
                role_name=rid.rsplit("/", 1)[-1],
                role_id=rid,
                scope=props.get("scope", ""),
                principal_id=props.get("principalId", ""),
                principal_type=props.get("principalType"),
            ))
        return assignments

    def _role_names_at_scope(self, scope_id: str, principal_id: str) -> list[str]:
        """Return role display names directly assigned to the user at a scope.

        Mirrors exploit's RG-scope discovery: only assignments at the given
        scope are considered (no inheritance expansion), filtered by principal.
        """
        assignments = self._role_assignments_at_scope(scope_id, principal_id)
        return self._role_names([a.role_id for a in assignments])

    def _collect_interesting_group(
        self,
        sub: Subscription,
        rg_obj: ResourceGroup,
        principal_id: str,
        assignments: list[RoleAssignment],
    ) -> dict | None:
        """Collect the exploit-phase inventory for one interesting resource group."""
        token = self._arm_token()
        if not token:
            return None
        try:
            from fenrir.exploit.discovery import collect_interesting_group as collect
            return collect(
                token,
                sub.subscription_id,
                sub.display_name,
                rg_obj.id,
                rg_obj.name,
                principal_id,
                assignments,
            )
        except Exception as e:
            self.result.errors.append(f"Exploit group collection for {rg_obj.name}: {e}")
            return None

    def collect_me(self) -> None:
        headers = self._graph_headers()
        if headers is None:
            return
        try:
            resp = requests.get(f"{GRAPH_API}/me", headers=headers, timeout=30)
            if resp.status_code == 200:
                self.result.me = resp.json()
        except requests.RequestException as e:
            self.result.errors.append(f"Failed to get /me: {e}")

    def collect_directory_roles(self) -> None:
        assignments = self._graph_get(
            "/roleManagement/directory/roleAssignments",
            {"$expand": "roleDefinition"}
        )
        if not assignments:
            return
        roles_map: dict[str, DirectoryRole] = {}
        for a in assignments:
            rd = a.get("roleDefinition", {})
            role_id = rd.get("id", a.get("roleDefinitionId", ""))
            if role_id not in roles_map:
                roles_map[role_id] = DirectoryRole(
                    id=role_id,
                    display_name=rd.get("displayName", "Unknown"),
                    description=rd.get("description"),
                    is_built_in=rd.get("isBuiltIn", False),
                    template_id=rd.get("templateId"),
                )
            self.result.directory_roles.append(DirectoryRoleAssignment(
                role=roles_map[role_id],
                principal_id=a.get("principalId"),
                principal_display_name=a.get("principalDisplayName"),
                directory_scope_id=a.get("directoryScopeId"),
            ))

    def collect_groups(self) -> None:
        groups = self._graph_get("/me/transitiveMemberOf")
        for g in groups:
            if g.get("@odata.type", "").endswith("group"):
                self.result.groups.append(Group(
                    id=g["id"],
                    display_name=g.get("displayName", "Unnamed"),
                    description=g.get("description"),
                    group_type="Unified" if g.get("groupTypes") and "Unified" in g["groupTypes"] else "Security",
                    security_enabled=g.get("securityEnabled", False),
                    mail_enabled=g.get("mailEnabled", False),
                    membership_rule=g.get("membershipRule"),
                    is_transitive_member=True,
                ))

    def collect_owned_apps(self) -> None:
        apps = self._graph_get("/me/ownedObjects")
        seen = set()
        for a in apps:
            otype = a.get("@odata.type", "")
            if "application" in otype and a["id"] not in seen:
                seen.add(a["id"])
                self.result.owned_applications.append(OwnedApplication(
                    id=a["id"],
                    display_name=a.get("displayName", "Unnamed"),
                    app_id=a.get("appId", ""),
                    publisher_domain=a.get("publisherDomain"),
                    sign_in_audience=a.get("signInAudience"),
                    created_date=a.get("createdDateTime"),
                    password_credentials=len(a.get("passwordCredentials", [])),
                    key_credentials=len(a.get("keyCredentials", [])),
                ))

    def collect_owned_service_principals(self) -> None:
        owned = self._graph_get("/me/ownedObjects")
        seen = set()
        for o in owned:
            otype = o.get("@odata.type", "")
            if "servicePrincipal" in otype and o["id"] not in seen:
                seen.add(o["id"])
                self.result.owned_service_principals.append(OwnedServicePrincipal(
                    id=o["id"],
                    display_name=o.get("displayName", o.get("appDisplayName", "Unnamed")),
                    app_id=o.get("appId", ""),
                    app_owner_org_id=o.get("appOwnerOrganizationId"),
                    service_principal_type=o.get("servicePrincipalType"),
                    password_credentials=len(o.get("passwordCredentials", [])),
                    key_credentials=len(o.get("keyCredentials", [])),
                ))

    def collect_managed_devices(self) -> None:
        devices = self._graph_get("/me/managedDevices", record_errors=False)
        for d in devices:
            self.result.managed_devices.append(ManagedDevice(
                id=d["id"],
                display_name=d.get("deviceName", d.get("displayName", "Unnamed")),
                device_category=d.get("deviceCategory"),
                operating_system=d.get("operatingSystem"),
                is_compliant=d.get("isCompliant"),
                is_managed=d.get("isManaged"),
                enrollment_type=d.get("enrollmentType"),
                trust_type=d.get("trustType"),
            ))

    def collect_domains(self) -> None:
        domains = self._graph_get("/domains")
        for d in domains:
            self.result.domains.append(Domain(
                id=d["id"],
                is_verified=d.get("isVerified", False),
                is_default=d.get("isDefault", False),
                authentication_type=d.get("authenticationType"),
            ))

    def collect_pim_roles(self) -> None:
        try:
            schedules = self._graph_get(
                "/roleManagement/directory/roleEligibilityScheduleInstances",
                record_errors=False,
            )
            for s in schedules:
                rd = s.get("roleDefinition", {})
                self.result.pim_roles.append(PimRoleAssignment(
                    role_name=rd.get("displayName", s.get("roleDefinitionId", "Unknown")),
                    principal_name=s.get("principalDisplayName"),
                    scope=s.get("directoryScopeId"),
                    status="Eligible",
                    start_time=s.get("startDateTime"),
                    end_time=s.get("endDateTime"),
                ))
        except Exception:
            pass

    def _collect_subscription_resources(self, sub: Subscription, principal_id: str) -> None:
        rgs_data = self._paginate_arm(
            f"/subscriptions/{sub.subscription_id}/resourceGroups",
            "2021-04-01",
        )
        if rgs_data is None:
            return

        def fetch_rg_resources(rg: dict) -> ResourceGroup | None:
            name = rg.get("name", "?")
            rg_obj = ResourceGroup(
                name=name,
                id=rg.get("id", ""),
                location=rg.get("location", ""),
                tags=rg.get("tags", {}),
            )
            rg_assignments = self._role_assignments_at_scope(rg.get("id", ""), principal_id)
            rg_obj.roles = self._role_names([a.role_id for a in rg_assignments])
            if INTERESTING_ROLE_NAMES.intersection(rg_obj.roles):
                rg_obj.exploit_group = self._collect_interesting_group(
                    sub, rg_obj, principal_id, rg_assignments
                )
            resources_data = self._paginate_arm(
                f"/subscriptions/{sub.subscription_id}/resourceGroups/{name}/resources",
                "2021-04-01",
            )
            if resources_data:
                for r in resources_data:
                    identity = r.get("identity") or {}
                    rg_obj.resources.append(Resource(
                        id=r.get("id", ""),
                        name=r.get("name", "Unnamed"),
                        type=r.get("type", "Unknown"),
                        location=r.get("location"),
                        tags=r.get("tags", {}),
                        roles=self._role_names_at_scope(r.get("id", ""), principal_id),
                        has_managed_identity=bool(identity.get("type")),
                        identity_type=identity.get("type") or None,
                    ))
            return rg_obj

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            futures = {pool.submit(fetch_rg_resources, rg): rg for rg in rgs_data}
            for future in as_completed(futures):
                try:
                    rg_obj = future.result()
                    if rg_obj:
                        sub.resource_groups.append(rg_obj)
                except Exception as e:
                    self.result.errors.append(f"Error processing RG: {e}")

    def collect_subscriptions(self) -> None:
        subs_data = self._paginate_arm("/subscriptions", "2020-01-01")
        if subs_data is None:
            return

        def process_sub(s: dict) -> Subscription | None:
            sub_id = s.get("subscriptionId", "")
            sub = Subscription(
                id=s.get("id", ""),
                subscription_id=sub_id,
                display_name=s.get("displayName", "Unnamed"),
                state=s.get("state", "Unknown"),
                tenant_id=s.get("tenantId"),
            )
            current_oid = (self.result.me or {}).get("id", "")
            sub.roles = self._role_names_at_scope(sub.id, current_oid)
            sub.resource_groups = []
            self._collect_subscription_resources(sub, current_oid)
            return sub

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            futures = {pool.submit(process_sub, s): s for s in subs_data}
            for future in as_completed(futures):
                try:
                    sub = future.result()
                    if sub:
                        self.result.subscriptions.append(sub)
                except Exception as e:
                    self.result.errors.append(f"Error processing subscription: {e}")

    def collect_management_groups(self) -> None:
        mg_data = self._arm_get(
            "/providers/Microsoft.Management/managementGroups",
            api_version="2020-05-01",
        )
        if not mg_data or not isinstance(mg_data, list):
            return
        for mg in mg_data:
            props = mg.get("properties", {})
            self.result.management_groups.append(ManagementGroup(
                id=mg.get("id", ""),
                name=mg.get("name", ""),
                display_name=props.get("displayName", mg.get("name", "Unnamed")),
                tenant_id=mg.get("properties", {}).get("tenantId"),
            ))

    def run(self) -> EnumerationResult:
        log.info("Starting full tenant enumeration")
        self.collect_me()
        self.collect_domains()
        self.collect_directory_roles()
        self.collect_pim_roles()
        self.collect_groups()
        self.collect_owned_apps()
        self.collect_owned_service_principals()
        self.collect_managed_devices()
        self.collect_management_groups()
        self.collect_subscriptions()
        log.info("Enumeration complete")
        return self.result
