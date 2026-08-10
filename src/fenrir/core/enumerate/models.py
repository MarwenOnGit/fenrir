from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class DirectoryRole:
    id: str
    display_name: str
    description: str | None = None
    is_built_in: bool = False
    template_id: str | None = None


@dataclass
class DirectoryRoleAssignment:
    role: DirectoryRole
    principal_id: str | None = None
    principal_display_name: str | None = None
    directory_scope_id: str | None = None


@dataclass
class Group:
    id: str
    display_name: str
    description: str | None = None
    group_type: str = "Security"  # Unified, Security, MailEnabled
    security_enabled: bool = False
    mail_enabled: bool = False
    membership_rule: str | None = None
    is_transitive_member: bool = False


@dataclass
class OwnedApplication:
    id: str
    display_name: str
    app_id: str
    publisher_domain: str | None = None
    sign_in_audience: str | None = None
    created_date: str | None = None
    password_credentials: int = 0
    key_credentials: int = 0


@dataclass
class OwnedServicePrincipal:
    id: str
    display_name: str
    app_id: str
    app_owner_org_id: str | None = None
    service_principal_type: str | None = None
    password_credentials: int = 0
    key_credentials: int = 0


@dataclass
class ManagedDevice:
    id: str
    display_name: str
    device_category: str | None = None
    operating_system: str | None = None
    is_compliant: bool | None = None
    is_managed: bool | None = None
    enrollment_type: str | None = None
    trust_type: str | None = None


@dataclass
class PimRoleAssignment:
    role_name: str
    principal_name: str | None = None
    scope: str | None = None
    status: str | None = None  # Active / Eligible
    start_time: str | None = None
    end_time: str | None = None


@dataclass
class Resource:
    id: str
    name: str
    type: str
    location: str | None = None
    tags: dict[str, str] = field(default_factory=dict)
    roles: list[str] = field(default_factory=list)
    has_managed_identity: bool = False
    identity_type: str | None = None


@dataclass
class ResourceGroup:
    name: str
    id: str
    location: str
    tags: dict[str, str] = field(default_factory=dict)
    resources: list[Resource] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    exploit_group: dict | None = None


@dataclass
class Subscription:
    id: str
    subscription_id: str
    display_name: str
    state: str
    tenant_id: str | None = None
    roles: list[str] = field(default_factory=list)
    resource_groups: list[ResourceGroup] = field(default_factory=list)


@dataclass
class ManagementGroup:
    id: str
    name: str
    display_name: str
    tenant_id: str | None = None
    children: list[ManagementGroup] = field(default_factory=list)


@dataclass
class Domain:
    id: str
    is_verified: bool = False
    is_default: bool = False
    authentication_type: str | None = None


@dataclass
class EnumerationResult:
    me: dict | None = None
    directory_roles: list[DirectoryRoleAssignment] = field(default_factory=list)
    pim_roles: list[PimRoleAssignment] = field(default_factory=list)
    groups: list[Group] = field(default_factory=list)
    owned_applications: list[OwnedApplication] = field(default_factory=list)
    owned_service_principals: list[OwnedServicePrincipal] = field(default_factory=list)
    managed_devices: list[ManagedDevice] = field(default_factory=list)
    subscriptions: list[Subscription] = field(default_factory=list)
    management_groups: list[ManagementGroup] = field(default_factory=list)
    domains: list[Domain] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
