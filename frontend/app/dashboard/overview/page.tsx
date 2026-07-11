"use client";

import useSWR from "swr";
import Link from "next/link";
import { ArrowRight, ShieldAlert, Server, Bell, Database, Flame, Loader2 } from "lucide-react";
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar, CartesianGrid } from "recharts";
import { Topbar } from "@/components/topbar";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { fetcher } from "@/lib/api";

type Overview = {
  servers: { total: number; active: number };
  cves: { total: number; added_30d: number };
  open_correlations: { by_severity: Record<string, number>; kev: number; total: number };
  alerts: { recent_30d: number; pending: number };
  trend_30d: { date: string; count: number }[];
};

type TopCve = {
  cve_id: string; title: string | null; severity: string | null;
  cvss_score: number | null; kev: boolean; exploit_available: boolean; risk_score: number | null;
};

type TopServer = { id: string; hostname: string; os_family: string | null; os_version: string | null; open_vulns: number };

export default function OverviewPage() {
  const { data: overview, isLoading } = useSWR<Overview>("/dashboard/overview", fetcher, { refreshInterval: 60_000 });
  const { data: topCves } = useSWR<TopCve[]>("/dashboard/top-cves?limit=8", fetcher);
  const { data: topServers } = useSWR<TopServer[]>("/dashboard/top-affected-servers?limit=6", fetcher);

  const trendData = (overview?.trend_30d || []).map((p) => ({
    date: p.date ? new Date(p.date).toLocaleDateString(undefined, { month: "short", day: "numeric" }) : "",
    count: p.count,
  }));

  const sevBuckets = overview?.open_correlations.by_severity || {};
  const sevData = ["critical", "high", "medium", "low", "none"].map((s) => ({
    severity: s,
    count: sevBuckets[s] || 0,
  }));

  return (
    <>
      <Topbar title="Overview" />
      <main className="flex-1 px-6 py-6 space-y-6">
        {isLoading ? (
          <div className="flex items-center gap-2 text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Loading…</div>
        ) : (
          <>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <StatCard
                icon={<Server className="h-4 w-4" />}
                label="Managed servers"
                value={overview?.servers.total ?? 0}
                hint={`${overview?.servers.active ?? 0} active`}
                href="/dashboard/servers"
              />
              <StatCard
                icon={<ShieldAlert className="h-4 w-4" />}
                label="Open vulnerabilities"
                value={overview?.open_correlations.total ?? 0}
                hint={`${overview?.open_correlations.kev ?? 0} on KEV list`}
                href="/dashboard/correlations"
                tone="destructive"
              />
              <StatCard
                icon={<Database className="h-4 w-4" />}
                label="CVEs in catalog"
                value={overview?.cves.total ?? 0}
                hint={`+${overview?.cves.added_30d ?? 0} in last 30d`}
                href="/dashboard/cves"
              />
              <StatCard
                icon={<Bell className="h-4 w-4" />}
                label="Alerts (30d)"
                value={overview?.alerts.recent_30d ?? 0}
                hint={`${overview?.alerts.pending ?? 0} pending dispatch`}
                href="/dashboard/alerts"
              />
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              <Card className="lg:col-span-2">
                <CardHeader>
                  <CardTitle className="text-base">New vulnerabilities — last 30 days</CardTitle>
                  <CardDescription>Correlations opened against your fleet, by day.</CardDescription>
                </CardHeader>
                <CardContent className="h-72">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={trendData} margin={{ left: -16, right: 12, top: 8 }}>
                      <CartesianGrid strokeDasharray="3 3" className="stroke-border" />
                      <XAxis dataKey="date" stroke="currentColor" fontSize={11} />
                      <YAxis stroke="currentColor" fontSize={11} allowDecimals={false} />
                      <Tooltip
                        contentStyle={{
                          background: "hsl(var(--popover))",
                          border: "1px solid hsl(var(--border))",
                          borderRadius: 8,
                          fontSize: 12,
                        }}
                      />
                      <Line type="monotone" dataKey="count" stroke="hsl(var(--primary))" strokeWidth={2} dot={false} />
                    </LineChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Open by severity</CardTitle>
                  <CardDescription>Across all monitored servers.</CardDescription>
                </CardHeader>
                <CardContent className="h-72">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={sevData} margin={{ left: -16, right: 12, top: 8 }}>
                      <CartesianGrid strokeDasharray="3 3" className="stroke-border" />
                      <XAxis dataKey="severity" stroke="currentColor" fontSize={11} />
                      <YAxis stroke="currentColor" fontSize={11} allowDecimals={false} />
                      <Tooltip
                        contentStyle={{
                          background: "hsl(var(--popover))",
                          border: "1px solid hsl(var(--border))",
                          borderRadius: 8,
                          fontSize: 12,
                        }}
                      />
                      <Bar dataKey="count" fill="hsl(var(--primary))" radius={[6, 6, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <Card>
                <CardHeader className="flex-row items-center justify-between">
                  <div>
                    <CardTitle className="text-base">Top CVEs by risk</CardTitle>
                    <CardDescription>Combined CVSS, KEV, and exposure.</CardDescription>
                  </div>
                  <Link href="/dashboard/cves" className="text-xs text-primary inline-flex items-center gap-1">
                    All CVEs <ArrowRight className="h-3 w-3" />
                  </Link>
                </CardHeader>
                <CardContent className="px-2">
                  <ul className="divide-y">
                    {(topCves || []).map((c) => (
                      <li key={c.cve_id}>
                        <Link
                          href={`/dashboard/cves/${c.cve_id}`}
                          className="flex items-center justify-between gap-3 px-3 py-2 hover:bg-accent/50 rounded-md"
                        >
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center gap-2">
                              <SeverityBadge value={c.severity} />
                              <span className="font-mono text-sm font-medium">{c.cve_id}</span>
                              {c.kev && <Flame className="h-3 w-3 text-sev-critical" aria-label="KEV" />}
                            </div>
                            <p className="text-xs text-muted-foreground truncate mt-0.5">
                              {c.title || "—"}
                            </p>
                          </div>
                          <div className="text-right">
                            <div className="text-sm font-semibold">{c.cvss_score?.toFixed(1) || "—"}</div>
                            <div className="text-[10px] text-muted-foreground">CVSS</div>
                          </div>
                        </Link>
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="flex-row items-center justify-between">
                  <div>
                    <CardTitle className="text-base">Most exposed servers</CardTitle>
                    <CardDescription>By open vulnerability count.</CardDescription>
                  </div>
                  <Link href="/dashboard/servers" className="text-xs text-primary inline-flex items-center gap-1">
                    All servers <ArrowRight className="h-3 w-3" />
                  </Link>
                </CardHeader>
                <CardContent className="px-2">
                  <ul className="divide-y">
                    {(topServers || []).map((s) => (
                      <li key={s.id}>
                        <Link
                          href={`/dashboard/servers/${s.id}`}
                          className="flex items-center justify-between gap-3 px-3 py-2 hover:bg-accent/50 rounded-md"
                        >
                          <div className="min-w-0">
                            <div className="font-medium text-sm">{s.hostname}</div>
                            <div className="text-xs text-muted-foreground">
                              {(s.os_family || "?").toUpperCase()} {s.os_version || ""}
                            </div>
                          </div>
                          <div className="text-right">
                            <div className="text-sm font-semibold text-sev-high">{s.open_vulns}</div>
                            <div className="text-[10px] text-muted-foreground">open</div>
                          </div>
                        </Link>
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            </div>
          </>
        )}
      </main>
    </>
  );
}

function StatCard({
  icon, label, value, hint, href, tone = "default",
}: {
  icon: React.ReactNode; label: string; value: number | string; hint?: string; href?: string;
  tone?: "default" | "destructive";
}) {
  const inner = (
    <Card className={tone === "destructive" ? "border-destructive/30" : ""}>
      <CardContent className="p-5">
        <div className="flex items-center gap-2 text-muted-foreground text-xs uppercase tracking-wide">
          {icon}
          {label}
        </div>
        <div className="mt-3 text-3xl font-semibold tracking-tight">{value}</div>
        {hint && <div className="text-xs text-muted-foreground mt-1">{hint}</div>}
      </CardContent>
    </Card>
  );
  return href ? <Link href={href}>{inner}</Link> : inner;
}
