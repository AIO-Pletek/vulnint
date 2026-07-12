"use client";

import * as React from "react";
import useSWR, { mutate } from "swr";
import { useParams } from "next/navigation";
import Link from "next/link";
import { ArrowLeft, RefreshCw, Loader2, Trash2, Copy, Check, FileDown } from "lucide-react";
import { Topbar } from "@/components/topbar";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { AuditFindingCard, AuditCategoryLabel } from "@/components/ui/audit-finding-card";
import * as Dialog from "@radix-ui/react-dialog";
import { api, auth, fetcher } from "@/lib/api";
import { formatDate, formatRelative } from "@/lib/utils";

type Server = {
  id: string; hostname: string; ip_address?: string; environment: string;
  os_family: string | null; os_version: string | null; kernel: string | null;
  cpanel_version: string | null; tags: string[]; is_active: boolean;
  last_seen_at: string | null; created_at: string; notes?: string | null;
};
type Correlation = {
  id: string; cve_id: string; package_name: string;
  installed_version: string; fixed_version: string | null;
  severity: string; status: string;
  cvss_score: number | null; kev: boolean; exploit_available: boolean;
  first_seen_at: string | null; last_seen_at: string | null;
};
type CorrelationPage = { items: Correlation[]; total: number; page: number; page_size: number };
type AuditFinding = {
  id: string; category: string; check_name: string;
  severity: string; status: string;
  title: string; description: string; remediation: string;
  evidence: Record<string, any>; created_at: string; updated_at: string;
};
type AuditFindingsResponse = { server_id: string; findings: AuditFinding[]; summary: Record<string, number> };

export default function ServerDetailPage() {
  const params = useParams<{ id: string }>();
  const id = params.id;
  const { data: server } = useSWR<Server>(`/servers/${id}`, fetcher);
  const { data: corr } = useSWR<CorrelationPage>(`/correlations?server_id=${id}&status=open&page_size=50`, fetcher);
  const { data: audit, mutate: mutateAudit } = useSWR<AuditFindingsResponse>(`/servers/${id}/findings`, fetcher);
  const [tokenDialog, setTokenDialog] = React.useState<string | null>(null);
  const [copied, setCopied] = React.useState(false);

  async function regenToken() {
    if (!confirm("Regenerate the agent token? The old one will stop working immediately.")) return;
    try {
      const res = await api<{ api_token: string }>(`/servers/${id}/regen-token`, { method: "POST" });
      setTokenDialog(res.api_token);
    } catch (e: any) {
      alert(e.message);
    }
  }

  async function updateFindingStatus(findingId: string, newStatus: string) {
    try {
      await api(`/servers/findings/${findingId}`, {
        method: "PATCH",
        json: { status: newStatus },
      });
      mutateAudit();
    } catch (e: any) {
      alert(e.message);
    }
  }

  async function softDelete() {
    if (!confirm("Remove this server from monitoring?")) return;
    try {
      await api(`/servers/${id}`, { method: "DELETE" });
      window.location.href = "/dashboard/servers";
    } catch (e: any) {
      alert(e.message);
    }
  }

  return (
    <>
      <Topbar title="Server detail" />
      <main className="flex-1 px-6 py-6 space-y-4">
        <Link href="/dashboard/servers" className="text-xs text-muted-foreground inline-flex items-center gap-1 hover:text-foreground">
          <ArrowLeft className="h-3 w-3" /> Back to servers
        </Link>

        {!server ? (
          <div className="flex items-center gap-2 text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Loading…</div>
        ) : (
          <>
            <Card>
              <CardContent className="p-6 flex flex-wrap items-start justify-between gap-4">
                <div>
                  <div className="flex items-center gap-3 mb-2">
                    <h2 className="text-2xl font-semibold tracking-tight">{server.hostname}</h2>
                    <Badge variant={server.environment === "production" ? "destructive" : "secondary"}>{server.environment}</Badge>
                    {server.is_active ? <span className="text-xs text-sev-low">● active</span> : <span className="text-xs text-muted-foreground">○ inactive</span>}
                  </div>
                  <div className="text-sm text-muted-foreground space-y-0.5">
                    {server.ip_address && <div className="font-mono">{server.ip_address}</div>}
                    <div>{(server.os_family || "?").toUpperCase()} {server.os_version || ""}</div>
                    {server.kernel && <div className="font-mono text-xs">kernel: {server.kernel}</div>}
                    {server.cpanel_version && <div className="font-mono text-xs">cPanel: {server.cpanel_version}</div>}
                  </div>
                </div>
                <div className="flex flex-col items-end gap-1 text-xs text-muted-foreground">
                  <div>Last check-in: <span className="text-foreground">{formatRelative(server.last_seen_at)}</span></div>
                  <div>Added: {formatDate(server.created_at).split(",")[0]}</div>
                  <div className="flex gap-2 mt-2">
                    <Button size="sm" variant="outline" asChild>
                      <button
                        onClick={async () => {
                          const token = auth.getAccess();
                          const res = await fetch(`/api/v1/servers/${id}/report`, {
                            headers: token ? { Authorization: `Bearer ${token}` } : {},
                          });
                          if (!res.ok) { alert('Failed to generate report'); return; }
                          const html = await res.text();
                          const w = window.open('', '_blank');
                          if (w) { w.document.write(html); w.document.close(); }
                        }}
                      >
                        <FileDown className="h-3 w-3" /> View
                      </button>
                    </Button>
                    <Button size="sm" variant="outline" asChild>
                      <button
                        onClick={async () => {
                          const token = auth.getAccess();
                          const res = await fetch(`/api/v1/servers/${id}/report?download=1`, {
                            headers: token ? { Authorization: `Bearer ${token}` } : {},
                          });
                          if (!res.ok) { alert('Failed to download'); return; }
                          const blob = await res.blob();
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement('a');
                          a.href = url; a.download = `vulnint-audit-${server?.hostname || id}.html`;
                          a.click(); URL.revokeObjectURL(url);
                        }}
                      >
                        <FileDown className="h-3 w-3" /> Save
                      </button>
                    </Button>
                    <Button size="sm" variant="outline" onClick={regenToken}>
                      <RefreshCw className="h-3 w-3" /> Regen token
                    </Button>
                    <Button size="sm" variant="destructive" onClick={softDelete}>
                      <Trash2 className="h-3 w-3" /> Remove
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">Open vulnerabilities ({corr?.total ?? 0})</CardTitle>
                <CardDescription>Detected from the latest agent inventory.</CardDescription>
              </CardHeader>
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>CVE</TableHead>
                      <TableHead>Severity</TableHead>
                      <TableHead>Package</TableHead>
                      <TableHead>Installed</TableHead>
                      <TableHead>Fixed in</TableHead>
                      <TableHead className="text-right">First seen</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {!corr ? (
                      <TableRow><TableCell colSpan={6} className="py-8 text-center text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin inline-block" /></TableCell></TableRow>
                    ) : corr.items.length === 0 ? (
                      <TableRow><TableCell colSpan={6} className="py-8 text-center text-muted-foreground">No open vulnerabilities. 🎉</TableCell></TableRow>
                    ) : (
                      corr.items.map((c) => (
                        <TableRow key={c.id}>
                          <TableCell>
                            <Link href={`/dashboard/cves/${c.cve_id}`} className="text-primary hover:underline font-mono text-xs font-semibold">
                              {c.cve_id}
                            </Link>
                          </TableCell>
                          <TableCell><SeverityBadge value={c.severity} /></TableCell>
                          <TableCell className="font-mono text-xs">{c.package_name}</TableCell>
                          <TableCell className="font-mono text-xs text-sev-high">{c.installed_version}</TableCell>
                          <TableCell className="font-mono text-xs text-sev-low">{c.fixed_version || "—"}</TableCell>
                          <TableCell className="text-right text-xs text-muted-foreground">{formatRelative(c.first_seen_at)}</TableCell>
                        </TableRow>
                      ))
                    )}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>

            {/* ─── Security Audit ──────────────────────────────────────────── */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base">
                  Security audit
                  {audit && audit.findings.length > 0 && ` (${audit.findings.filter(f => f.status === 'open').length} open)`}
                </CardTitle>
                <CardDescription>
                  Configuration and posture checks from the latest agent run.
                </CardDescription>
              </CardHeader>
              <CardContent>
                {!audit ? (
                  <div className="flex items-center gap-2 text-muted-foreground py-8 justify-center">
                    <Loader2 className="h-4 w-4 animate-spin" /> Loading audit data…
                  </div>
                ) : audit.findings.length === 0 ? (
                  <div className="py-8 text-center text-muted-foreground">
                    No security issues found. System looks well-configured. ✅
                  </div>
                ) : (
                  <>
                    {/* Severity summary */}
                    <div className="flex items-center gap-3 mb-4 flex-wrap">
                      {["critical", "high", "medium", "low"].map((s) =>
                        audit.summary[s] ? (
                          <div key={s} className="flex items-center gap-1 text-xs">
                            <SeverityBadge value={s} />
                            <span className="font-semibold">{audit.summary[s]}</span>
                          </div>
                        ) : null
                      )}
                    </div>

                    {/* Grouped by category */}
                    {(["ssh", "firewall", "updates", "services", "misc"] as const).map((cat) => {
                      const items = audit.findings.filter((f) => f.category === cat);
                      if (items.length === 0) return null;
                      return (
                        <div key={cat} className="mb-3 last:mb-0">
                          <AuditCategoryLabel category={cat} />
                          <div className="mt-1 space-y-1.5">
                            {items.map((f) => (
                              <AuditFindingCard
                                key={f.id}
                                finding={f}
                                onAcknowledge={(id) => updateFindingStatus(id, "acknowledged")}
                                onIgnore={(id) => updateFindingStatus(id, "ignored")}
                              />
                            ))}
                          </div>
                        </div>
                      );
                    })}
                  </>
                )}
              </CardContent>
            </Card>
          </>
        )}
      </main>

      <Dialog.Root open={!!tokenDialog} onOpenChange={() => setTokenDialog(null)}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm" />
          <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-full max-w-lg -translate-x-1/2 -translate-y-1/2 rounded-lg border bg-card p-6 shadow-lg">
            <Dialog.Title className="text-base font-semibold">New agent token</Dialog.Title>
            <Dialog.Description className="text-sm text-muted-foreground mb-4">
              Update the agent on this server with the token below. The previous token has been revoked.
            </Dialog.Description>
            <div className="rounded-md bg-muted p-3 font-mono text-xs break-all border">{tokenDialog}</div>
            <div className="flex justify-end gap-2 mt-4">
              <Button variant="outline" size="sm" onClick={() => {
                navigator.clipboard.writeText(tokenDialog!);
                setCopied(true); setTimeout(() => setCopied(false), 1500);
              }}>
                {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                {copied ? "Copied" : "Copy"}
              </Button>
              <Button onClick={() => setTokenDialog(null)}>Done</Button>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
    </>
  );
}
