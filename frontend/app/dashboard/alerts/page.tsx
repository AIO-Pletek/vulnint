"use client";

import * as React from "react";
import useSWR from "swr";
import { Loader2, Send } from "lucide-react";
import { Topbar } from "@/components/topbar";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { Badge } from "@/components/ui/badge";
import { api, fetcher } from "@/lib/api";
import { formatRelative } from "@/lib/utils";

type Alert = {
  id: string; title: string; body: string;
  severity: string; channel: string; status: string;
  error: string | null; sent_at: string | null; created_at: string;
};
type Page = { items: Alert[]; total: number; page: number; page_size: number };

const STATUS = ["pending", "sent", "failed", "suppressed"];

const STATUS_VARIANT: Record<string, "default" | "secondary" | "destructive"> = {
  pending: "secondary",
  sent: "default",
  failed: "destructive",
  suppressed: "secondary",
};

export default function AlertsPage() {
  const [status, setStatus] = React.useState<string[]>([]);
  const params = new URLSearchParams({ page_size: "50" });
  status.forEach((s) => params.append("status", s));
  const { data, isLoading, mutate: revalidate } = useSWR<Page>(`/alerts?${params.toString()}`, fetcher, {
    refreshInterval: 15_000,
  });
  const [dispatching, setDispatching] = React.useState(false);

  async function dispatchPending() {
    setDispatching(true);
    try {
      await api(`/alerts/dispatch-pending`, { method: "POST" });
      setTimeout(() => revalidate(), 1500);
    } catch (e: any) {
      alert(e.message);
    } finally {
      setDispatching(false);
    }
  }

  return (
    <>
      <Topbar title="Alerts" />
      <main className="flex-1 px-6 py-6 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex flex-wrap gap-2">
            {STATUS.map((s) => (
              <button key={s} type="button"
                onClick={() => setStatus(status.includes(s) ? status.filter(x => x !== s) : [...status, s])}
                className={`rounded-md border px-3 py-1.5 text-xs font-medium transition-colors ${
                  status.includes(s) ? "border-primary bg-primary/10" : "border-input bg-background hover:bg-accent"
                }`}>
                {s}
              </button>
            ))}
          </div>
          <Button onClick={dispatchPending} disabled={dispatching} size="sm">
            {dispatching ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
            Dispatch pending
          </Button>
        </div>

        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Severity</TableHead>
                  <TableHead>Title</TableHead>
                  <TableHead>Channel</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead>Sent</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {isLoading && !data ? (
                  <TableRow><TableCell colSpan={6} className="py-10 text-center text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin inline-block" /></TableCell></TableRow>
                ) : (data?.items || []).length === 0 ? (
                  <TableRow><TableCell colSpan={6} className="py-10 text-center text-muted-foreground">No alerts.</TableCell></TableRow>
                ) : (
                  data!.items.map((a) => (
                    <TableRow key={a.id}>
                      <TableCell><SeverityBadge value={a.severity} /></TableCell>
                      <TableCell>
                        <div className="text-sm font-medium">{a.title}</div>
                        <div className="text-xs text-muted-foreground truncate max-w-md">{a.body}</div>
                        {a.error && <div className="text-xs text-destructive font-mono mt-1">{a.error}</div>}
                      </TableCell>
                      <TableCell><Badge variant="secondary">{a.channel}</Badge></TableCell>
                      <TableCell><Badge variant={STATUS_VARIANT[a.status] || "secondary"}>{a.status}</Badge></TableCell>
                      <TableCell className="text-xs text-muted-foreground">{formatRelative(a.created_at)}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{formatRelative(a.sent_at)}</TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </main>
    </>
  );
}
