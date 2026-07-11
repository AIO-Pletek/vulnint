"use client";

import * as React from "react";
import Link from "next/link";
import useSWR, { mutate } from "swr";
import { Loader2, ChevronLeft, ChevronRight, Flame, Bug } from "lucide-react";
import { Topbar } from "@/components/topbar";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { api, fetcher } from "@/lib/api";
import { formatRelative } from "@/lib/utils";

type Correlation = {
  id: string; cve_id: string; hostname: string;
  package_name: string; installed_version: string; fixed_version: string | null;
  severity: string; status: string;
  cvss_score: number | null; kev: boolean; exploit_available: boolean;
  first_seen_at: string | null;
};
type Page = { items: Correlation[]; total: number; page: number; page_size: number };

const SEV = ["critical", "high", "medium", "low"] as const;
const STATUS = ["open", "fixed", "ignored", "accepted_risk"] as const;

export default function CorrelationsPage() {
  const [sev, setSev] = React.useState<string[]>([]);
  const [status, setStatus] = React.useState<string[]>(["open"]);
  const [kev, setKev] = React.useState(false);
  const [page, setPage] = React.useState(1);
  const pageSize = 30;

  React.useEffect(() => setPage(1), [sev, status, kev]);

  const params = new URLSearchParams();
  sev.forEach((s) => params.append("severity", s));
  status.forEach((s) => params.append("status", s));
  if (kev) params.set("kev", "true");
  params.set("page", String(page));
  params.set("page_size", String(pageSize));

  const key = `/correlations?${params.toString()}`;
  const { data, isLoading } = useSWR<Page>(key, fetcher);
  const totalPages = data ? Math.max(1, Math.ceil(data.total / pageSize)) : 1;

  async function changeStatus(id: string, newStatus: string) {
    try {
      await api(`/correlations/${id}`, { method: "PATCH", json: { status: newStatus } });
      mutate(key);
    } catch (e: any) {
      alert(e.message);
    }
  }

  return (
    <>
      <Topbar title="Vulnerabilities" />
      <main className="flex-1 px-6 py-6 space-y-4">
        <Card>
          <CardContent className="p-4 flex flex-wrap gap-2 items-center">
            <span className="text-xs text-muted-foreground uppercase tracking-wide mr-1">Severity</span>
            {SEV.map((s) => (
              <Toggle key={s} active={sev.includes(s)} onClick={() => toggle(sev, s, setSev)}>
                <SeverityBadge value={s} />
              </Toggle>
            ))}
            <span className="w-2" />
            <span className="text-xs text-muted-foreground uppercase tracking-wide mr-1">Status</span>
            {STATUS.map((s) => (
              <Toggle key={s} active={status.includes(s)} onClick={() => toggle(status, s, setStatus)}>
                <span className="px-2 py-0.5 text-xs font-medium">{s.replace("_", " ")}</span>
              </Toggle>
            ))}
            <span className="w-2" />
            <Toggle active={kev} onClick={() => setKev(!kev)}>
              <span className="px-2 py-0.5 text-xs font-medium inline-flex items-center gap-1">
                <Flame className="h-3 w-3 text-sev-critical" /> KEV only
              </span>
            </Toggle>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>CVE</TableHead>
                  <TableHead>Server</TableHead>
                  <TableHead>Package</TableHead>
                  <TableHead>Installed → Fixed</TableHead>
                  <TableHead className="w-[100px]">Severity</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>First seen</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {isLoading && !data ? (
                  <TableRow><TableCell colSpan={8} className="py-10 text-center text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin inline-block" /></TableCell></TableRow>
                ) : (data?.items || []).length === 0 ? (
                  <TableRow><TableCell colSpan={8} className="py-10 text-center text-muted-foreground">Nothing matches.</TableCell></TableRow>
                ) : (
                  data!.items.map((c) => (
                    <TableRow key={c.id}>
                      <TableCell className="font-mono text-xs">
                        <Link href={`/dashboard/cves/${c.cve_id}`} className="text-primary hover:underline font-semibold">{c.cve_id}</Link>
                        <div className="flex gap-1 mt-0.5">
                          {c.kev && <Flame className="h-3 w-3 text-sev-critical" />}
                          {c.exploit_available && <Bug className="h-3 w-3 text-sev-high" />}
                          {c.cvss_score && <span className="text-[10px] text-muted-foreground">{c.cvss_score.toFixed(1)}</span>}
                        </div>
                      </TableCell>
                      <TableCell className="text-sm">{c.hostname}</TableCell>
                      <TableCell className="font-mono text-xs">{c.package_name}</TableCell>
                      <TableCell className="font-mono text-[11px]">
                        <span className="text-sev-high">{c.installed_version}</span>
                        <span className="text-muted-foreground mx-1">→</span>
                        <span className="text-sev-low">{c.fixed_version || "?"}</span>
                      </TableCell>
                      <TableCell><SeverityBadge value={c.severity} /></TableCell>
                      <TableCell className="text-xs uppercase tracking-wide">{c.status.replace("_", " ")}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{formatRelative(c.first_seen_at)}</TableCell>
                      <TableCell className="text-right">
                        <select
                          value={c.status}
                          onChange={(e) => changeStatus(c.id, e.target.value)}
                          className="h-8 rounded-md border border-input bg-background px-2 text-xs"
                        >
                          {STATUS.map((s) => (
                            <option key={s} value={s}>{s.replace("_", " ")}</option>
                          ))}
                        </select>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        <div className="flex items-center justify-between text-sm text-muted-foreground">
          <div>{data ? `${data.total.toLocaleString()} total` : "—"}</div>
          <div className="flex gap-2 items-center">
            <Button variant="outline" size="sm" onClick={() => setPage(Math.max(1, page - 1))} disabled={page <= 1}>
              <ChevronLeft className="h-4 w-4" /> Prev
            </Button>
            <span className="text-xs">Page {page} / {totalPages}</span>
            <Button variant="outline" size="sm" onClick={() => setPage(Math.min(totalPages, page + 1))} disabled={page >= totalPages}>
              Next <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </main>
    </>
  );
}

function toggle<T extends string>(arr: T[], v: T, set: (n: T[]) => void) {
  set(arr.includes(v) ? arr.filter((x) => x !== v) : [...arr, v]);
}
function Toggle({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button type="button" onClick={onClick}
      className={`rounded-md border transition-colors ${active ? "border-primary bg-primary/10" : "border-input bg-background hover:bg-accent"}`}>
      {children}
    </button>
  );
}
