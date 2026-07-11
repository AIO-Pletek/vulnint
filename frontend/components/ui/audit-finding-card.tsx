"use client";

import * as React from "react";
import { ChevronDown, ChevronUp } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { SeverityBadge } from "@/components/ui/severity-badge";

type Finding = {
  id: string;
  category: string;
  check_name: string;
  severity: string;
  status: string;
  title: string;
  description: string;
  remediation: string;
  created_at: string;
};

const CATEGORY_LABELS: Record<string, string> = {
  ssh: "SSH",
  firewall: "Firewall",
  updates: "Updates",
  services: "Services",
  misc: "Misc",
};

export function AuditFindingCard({
  finding,
  onAcknowledge,
  onIgnore,
}: {
  finding: Finding;
  onAcknowledge?: (id: string) => void;
  onIgnore?: (id: string) => void;
}) {
  const [expanded, setExpanded] = React.useState(false);

  return (
    <div className="border rounded-lg p-3 space-y-2 hover:bg-accent/30 transition-colors">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2 min-w-0 flex-1">
          <SeverityBadge value={finding.severity} />
          <span className="text-sm font-medium truncate">{finding.title}</span>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {finding.status === "open" && onAcknowledge && (
            <button
              onClick={() => onAcknowledge(finding.id)}
              className="text-xs text-muted-foreground hover:text-foreground px-1.5 py-0.5 rounded border border-input"
            >
              Ack
            </button>
          )}
          {finding.status === "open" && onIgnore && (
            <button
              onClick={() => onIgnore(finding.id)}
              className="text-xs text-muted-foreground hover:text-foreground px-1.5 py-0.5 rounded border border-input"
            >
              Ignore
            </button>
          )}
          {finding.status !== "open" && (
            <Badge variant="secondary">{finding.status}</Badge>
          )}
          <button
            onClick={() => setExpanded(!expanded)}
            className="text-muted-foreground hover:text-foreground p-0.5"
            aria-label={expanded ? "Collapse" : "Expand"}
          >
            {expanded ? (
              <ChevronUp className="h-4 w-4" />
            ) : (
              <ChevronDown className="h-4 w-4" />
            )}
          </button>
        </div>
      </div>

      {expanded && (
        <div className="space-y-2 pt-1 text-sm">
          <p className="text-muted-foreground">{finding.description}</p>
          {finding.remediation && (
            <div className="rounded-md bg-muted px-3 py-2 text-xs">
              <span className="font-semibold">Fix: </span>
              {finding.remediation}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export function AuditCategoryLabel({ category }: { category: string }) {
  return (
    <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
      {CATEGORY_LABELS[category] || category}
    </span>
  );
}
