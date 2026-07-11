"use client";

import useSWR from "swr";
import { useParams } from "next/navigation";
import Link from "next/link";
import { ArrowLeft, ExternalLink, Flame, Bug, Loader2 } from "lucide-react";
import { Topbar } from "@/components/topbar";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { fetcher } from "@/lib/api";
import { formatDate } from "@/lib/utils";

type CveDetail = {
  cve_id: string; title?: string | null; description?: string | null;
  severity?: string | null; cvss_score?: number | null; cvss_vector?: string | null; cvss_version?: string | null;
  cwe?: string[] | null; references?: string[] | null;
  kev: boolean; exploit_available: boolean; risk_score?: number | null;
  published_at?: string | null; modified_at?: string | null;
  affected_products?: AffectedProduct[];
};
type AffectedProduct = {
  os_family?: string | null; vendor?: string | null; product?: string | null;
  package_name?: string | null;
  version_introduced?: string | null; version_fixed?: string | null;
  release?: string | null;
};
type Advisory = { id: string; advisory_id: string; source: string; title?: string | null; url?: string | null; published_at?: string | null };
type Exploit = { source: string; external_id?: string | null; url?: string | null; published_at?: string | null };

export default function CveDetailPage() {
  const params = useParams<{ id: string }>();
  const id = params.id;
  const { data: cve, isLoading } = useSWR<CveDetail>(`/cves/${id}`, fetcher);
  const { data: advisories } = useSWR<Advisory[]>(`/cves/${id}/advisories`, fetcher);
  const { data: exploits } = useSWR<Exploit[]>(`/cves/${id}/exploits`, fetcher);

  return (
    <>
      <Topbar title="CVE Detail" />
      <main className="flex-1 px-6 py-6 space-y-4">
        <Link href="/dashboard/cves" className="text-xs text-muted-foreground inline-flex items-center gap-1 hover:text-foreground">
          <ArrowLeft className="h-3 w-3" /> Back to CVEs
        </Link>

        {isLoading || !cve ? (
          <div className="flex items-center gap-2 text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Loading…</div>
        ) : (
          <>
            <Card>
              <CardContent className="p-6">
                <div className="flex flex-wrap items-center gap-3 mb-2">
                  <SeverityBadge value={cve.severity} />
                  <span className="font-mono text-xl font-bold">{cve.cve_id}</span>
                  {cve.kev && (
                    <span className="inline-flex items-center gap-1 text-xs font-bold rounded-md bg-sev-critical text-white px-2 py-1">
                      <Flame className="h-3 w-3" /> CISA KEV
                    </span>
                  )}
                  {cve.exploit_available && (
                    <span className="inline-flex items-center gap-1 text-xs font-bold rounded-md bg-sev-high text-white px-2 py-1">
                      <Bug className="h-3 w-3" /> Exploit available
                    </span>
                  )}
                </div>
                {cve.title && <h2 className="text-lg font-semibold mt-1">{cve.title}</h2>}
                {cve.description && <p className="text-sm text-muted-foreground mt-3 leading-relaxed">{cve.description}</p>}

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-6">
                  <Stat label="CVSS Score" value={cve.cvss_score?.toFixed(1) || "—"} sub={cve.cvss_version || ""} />
                  <Stat label="Risk Score" value={cve.risk_score?.toFixed(0) || "—"} sub="0–100" />
                  <Stat label="Published" value={formatDate(cve.published_at).split(",")[0]} sub={cve.published_at ? new Date(cve.published_at).getFullYear().toString() : ""} />
                  <Stat label="Modified" value={formatDate(cve.modified_at).split(",")[0]} sub="" />
                </div>

                {cve.cvss_vector && (
                  <div className="mt-4 text-xs font-mono break-all rounded-md bg-muted/50 px-3 py-2">{cve.cvss_vector}</div>
                )}
                {cve.cwe && cve.cwe.length > 0 && (
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    {cve.cwe.map((c) => (
                      <span key={c} className="text-[11px] font-mono rounded-md bg-secondary px-2 py-0.5">{c}</span>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">Affected products</CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>OS / Release</TableHead>
                      <TableHead>Vendor / Product</TableHead>
                      <TableHead>Package</TableHead>
                      <TableHead>Introduced</TableHead>
                      <TableHead>Fixed in</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {(cve.affected_products || []).length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={5} className="text-center text-muted-foreground py-8">No affected products on file.</TableCell>
                      </TableRow>
                    ) : (
                      cve.affected_products!.map((a, i) => (
                        <TableRow key={i}>
                          <TableCell className="text-xs">
                            <div>{(a.os_family || "—").toUpperCase()}</div>
                            {a.release && <div className="text-muted-foreground">{a.release}</div>}
                          </TableCell>
                          <TableCell className="text-xs">{[a.vendor, a.product].filter(Boolean).join(" / ") || "—"}</TableCell>
                          <TableCell className="font-mono text-xs">{a.package_name || "—"}</TableCell>
                          <TableCell className="font-mono text-xs">{a.version_introduced || "—"}</TableCell>
                          <TableCell className="font-mono text-xs text-sev-low">{a.version_fixed || "—"}</TableCell>
                        </TableRow>
                      ))
                    )}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Vendor advisories</CardTitle>
                </CardHeader>
                <CardContent className="p-3">
                  {(advisories || []).length === 0 ? (
                    <p className="text-sm text-muted-foreground">No advisories.</p>
                  ) : (
                    <ul className="space-y-2">
                      {advisories!.map((a) => (
                        <li key={a.id} className="text-sm">
                          <a href={a.url || "#"} target="_blank" rel="noopener noreferrer"
                             className="text-primary hover:underline inline-flex items-center gap-1">
                            <span className="font-mono text-xs uppercase rounded bg-secondary px-1.5 py-0.5">{a.source}</span>
                            <span>{a.advisory_id}</span>
                            <ExternalLink className="h-3 w-3" />
                          </a>
                          {a.title && <span className="text-muted-foreground ml-2">{a.title}</span>}
                        </li>
                      ))}
                    </ul>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Exploit intelligence</CardTitle>
                </CardHeader>
                <CardContent className="p-3">
                  {(exploits || []).length === 0 ? (
                    <p className="text-sm text-muted-foreground">No known public exploits indexed.</p>
                  ) : (
                    <ul className="space-y-2">
                      {exploits!.map((e, i) => (
                        <li key={i} className="text-sm">
                          <span className="font-mono text-xs uppercase rounded bg-secondary px-1.5 py-0.5 mr-2">{e.source}</span>
                          {e.url ? (
                            <a href={e.url} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline inline-flex items-center gap-1">
                              {e.external_id || "Reference"} <ExternalLink className="h-3 w-3" />
                            </a>
                          ) : (
                            <span>{e.external_id || "Reference"}</span>
                          )}
                        </li>
                      ))}
                    </ul>
                  )}
                </CardContent>
              </Card>
            </div>

            {cve.references && cve.references.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">References</CardTitle>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-1.5 text-sm">
                    {cve.references.map((r, i) => (
                      <li key={i} className="truncate">
                        <a href={r} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline inline-flex items-center gap-1">
                          {r} <ExternalLink className="h-3 w-3 flex-shrink-0" />
                        </a>
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            )}
          </>
        )}
      </main>
    </>
  );
}

function Stat({ label, value, sub }: { label: string; value: React.ReactNode; sub?: string }) {
  return (
    <div>
      <div className="text-xs text-muted-foreground uppercase tracking-wide">{label}</div>
      <div className="text-2xl font-semibold tabular-nums mt-1">{value}</div>
      {sub && <div className="text-[11px] text-muted-foreground">{sub}</div>}
    </div>
  );
}
