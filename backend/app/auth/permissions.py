"""Static permission catalog. Used by RBAC."""

class Perm:
    # Servers
    SERVER_READ = "server:read"
    SERVER_WRITE = "server:write"
    SERVER_DELETE = "server:delete"

    # CVEs
    CVE_READ = "cve:read"
    CVE_WRITE = "cve:write"

    # Correlations
    CORRELATION_READ = "correlation:read"
    CORRELATION_WRITE = "correlation:write"

    # Alerts
    ALERT_READ = "alert:read"
    ALERT_WRITE = "alert:write"
    ALERT_RULE_WRITE = "alert_rule:write"

    # Users / RBAC
    USER_READ = "user:read"
    USER_WRITE = "user:write"
    ROLE_WRITE = "role:write"

    # Inventory ingest (for agents)
    INVENTORY_INGEST = "inventory:ingest"

    # Audit
    AUDIT_READ = "audit:read"

    # System / feeds
    FEEDS_TRIGGER = "feeds:trigger"


ALL_PERMISSIONS = [
    (Perm.SERVER_READ, "Read server inventory"),
    (Perm.SERVER_WRITE, "Create/update servers"),
    (Perm.SERVER_DELETE, "Delete servers"),
    (Perm.CVE_READ, "Read CVE data"),
    (Perm.CVE_WRITE, "Edit CVE data"),
    (Perm.CORRELATION_READ, "Read correlations"),
    (Perm.CORRELATION_WRITE, "Update correlation status"),
    (Perm.ALERT_READ, "Read alerts"),
    (Perm.ALERT_WRITE, "Manage alerts"),
    (Perm.ALERT_RULE_WRITE, "Manage alert rules"),
    (Perm.USER_READ, "Read users"),
    (Perm.USER_WRITE, "Manage users"),
    (Perm.ROLE_WRITE, "Manage roles"),
    (Perm.INVENTORY_INGEST, "Ingest agent inventory"),
    (Perm.AUDIT_READ, "Read audit logs"),
    (Perm.FEEDS_TRIGGER, "Manually trigger feeds"),
]


# Default seed roles
DEFAULT_ROLES = {
    "admin": [p for p, _ in ALL_PERMISSIONS],
    "analyst": [
        Perm.SERVER_READ, Perm.CVE_READ, Perm.CORRELATION_READ, Perm.CORRELATION_WRITE,
        Perm.ALERT_READ, Perm.AUDIT_READ,
    ],
    "viewer": [
        Perm.SERVER_READ, Perm.CVE_READ, Perm.CORRELATION_READ, Perm.ALERT_READ,
    ],
    "agent": [Perm.INVENTORY_INGEST],
}
