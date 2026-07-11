"use client";

import * as React from "react";
import Link from "next/link";
import useSWR from "swr";
import { Search, Flame, Bug, Loader2, ChevronLeft, ChevronRight } from "lucide-react";
import { Topbar } from "@/components/topbar";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { fetcher } from "@/lib/api";
import { formatRelative } from "@/lib/utils";

type CveDoc = {
  cve_id: string; title?: string | null; description?: string | null;
  severity?: string | null; cvss_score?: number | null;
  kev?: boolean; exploit_available?: boolean; risk_score?: number | null;
  vendors?: string[]; products?: string[]; os_targets?: string[];
  modified_at?: string | null;
};

type CveSearchResponse = {
  total: number; page: number; size: number;
  items: CveDoc[];
  aggregations?: { by_severity?: Record<string, number>; by_os_family?: Record<string, number>; kev_count?: number; exploit_count?: number };
};

const SEV_FILTERS = ["critical", "high", "medium", "low"] as const;
const OS_FILTERS = ["ubuntu", "debian", "almalinux", "rocky", "cloudlinux", "windows", "cpanel"] as const;

export default function CvesPage() {
  const [q, setQ] = React.useState("");
  const [debouncedQ, setDebouncedQ] = React.useState("");
  const [sev, setSev] = React.useState<string[]>([]);
  const [os, setOs] = React.useState<string[]>([]);
  const [kev, setKev] = React.useState(false);
  const [exploit, setExploit] = React.useState(false);
  const [page, setPage] = React.useState(1);
  const pageSize = 25;

  React.useEffect(() => {
    const t = setTimeout(() => setDebouncedQ(q), 300);
    return () => clearTimeout(t);
  }, [q]);

  React.useEffect(() => setPage(1), [debouncedQ, sev, os, kev, exploit]);

  const params = new URLSearchParams();
  if (debouncedQ) params.set("q", debouncedQ);
  sev.forEach((s) => params.append("severity", s));
  os.forEach((o) => params.append("os_family", o));
  if (kev) params.set("kev", "true");
  if (exploit) params.set("exploit_available", "true");
  params.set("page", String(page));
  params.set("page_size", String(pageSize));

  const { data, isLoading } = useSWR<CveSearchResponse>(`/cves?${params.toString()}`, fetcher, {
    keepPreviousData: true,
  });

  const totalPages = data ? Math.max(1, Math.ceil(data.total / pageSize)) : 1;

  return (
    <>
      <Topbar title="CVE Explorer" />
      <main className="flex-1 px-6 py-6 space-y-4">
        <Card>
          <CardContent className="p-4 space-y-3">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search by CVE ID, product, vendor, or keyword…"
                value={q}
                onChange={(e) => setQ(e.target.value)}
                className="pl-9"
              />
            </div>
            <div className="flex flex-wrap gap-2 items-center">
              <span className="text-xs text-muted-foreground uppercase tracking-wide mr-1">Severity</span>
              {SEV_FILTERS.map((s) => (
                <Toggle key={s} active={sev.includes(s)} onClick={() => toggle(sev, s, setSev)}>
                  <SeverityBadge value={s} />
                </Toggle>
              ))}
              <span className="w-2" />
              <span className="text-xs text-muted-foreground uppercase tracking-wide mr-1">OS</span>
              {OS_FILTERS.map((o) => (
                <Toggle key={o} active={os.includes(o)} onClick={() => toggle(os, o, setOs)}>
                  <span className="px-2 py-0.5 text-xs font-medium">{o}</span>
                </Toggle>
              ))}
              <span className="w-2" />
              <Toggle active={kev} onClick={() => setKev(!kev)}>
                <span className="px-2 py-0.5 text-xs font-medium inline-flex items-center gap-1">
                  <Flame className="h-3 w-3 text-sev-critical" /> KEV
                </span>
              </Toggle>
              <Toggle active={exploit} onClick={() => setExploit(!exploit)}>
                <span className="px-2 py-0.5 text-xs font-medium inline-flex items-center gap-1">
                  <Bug className="h-3 w-3" /> Exploit known
                </span>
              </Toggle>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[140px]">CVE</TableHead>
                  <TableHead>Title</TableHead>
                  <TableHead className="w-[100px]">Severity</TableHead>
                  <TableHead className="w-[80px] text-right">CVSS</TableHead>
                  <TableHead className="w-[120px]">Flags</TableHead>
                  <TableHead className="w-[120px] text-right">Modified</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {isLoading && !data ? (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center text-muted-foreground py-10">
                      <Loader2 className="h-4 w-4 animate-spin inline-block mr-2" /> Loading…
                    </TableCell>
                  </TableRow>
                ) : (data?.items || []).length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center text-muted-foreground py-10">
                      No matching CVEs.
                    </TableCell>
                  </TableRow>
                ) : (
                  (data?.items || []).map((c) => (
                    <TableRow key={c.cve_id} className="cursor-pointer">
                      <TableCell className="font-mono text-xs font-semibold">
                        <Link href={`/dashboard/cves/${c.cve_id}`} className="text-primary hover:underline">
                          {c.cve_id}
                        </Link>
                      </TableCell>
                      <TableCell className="max-w-md">
                        <div className="truncate text-sm">{c.title || c.description?.slice(0, 140) || "—"}</div>
                        {c.products && c.products.length > 0 && (
                          <div className="text-[11px] text-muted-foreground truncate mt-0.5">
                            {c.products.slice(0, 4).join(" · ")}
                          </div>
                        )}
                      </TableCell>
                      <TableCell><SeverityBadge value={c.severity} /></TableCell>
                      <TableCell className="text-right tabular-nums text-sm">
                        {c.cvss_score?.toFixed(1) || "—"}
                      </TableCell>
                      <TableCell>
                        <div className="flex gap-1">
                          {c.kev && <Flame className="h-3.5 w-3.5 text-sev-critical" aria-label="KEV" />}
                          {c.exploit_available && <Bug className="h-3.5 w-3.5 text-sev-high" aria-label="Exploit known" />}
                        </div>
                      </TableCell>
                      <TableCell className="text-right text-xs text-muted-foreground tabular-nums">
                        {formatRelative(c.modified_at)}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        <div className="flex items-center justify-between text-sm text-muted-foreground">
          <div>
            {data ? (
              <>Showing <strong className="text-foreground">{(page - 1) * pageSize + 1}–{Math.min(page * pageSize, data.total)}</strong> of {data.total.toLocaleString()}</>
            ) : "—"}
          </div>
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
    <button
      type="button"
      onClick={onClick}
      className={`rounded-md border transition-colors ${active ? "border-primary bg-primary/10" : "border-input bg-background hover:bg-accent"}`}
    >
      {children}
    </button>
  );
}
