"use client";

import * as React from "react";
import useSWR from "swr";
import { Play, Database, RefreshCw, Loader2 } from "lucide-react";
import { Topbar } from "@/components/topbar";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { api, fetcher } from "@/lib/api";

type Feed = { name: string; class: string };

export default function FeedsPage() {
  const { data, isLoading } = useSWR<Feed[]>("/feeds", fetcher);
  const [running, setRunning] = React.useState<string | null>(null);
  const [msg, setMsg] = React.useState<string | null>(null);

  async function run(name: string) {
    setRunning(name); setMsg(null);
    try {
      const res = await api<{ task_id: string }>(`/feeds/${name}/run`, { method: "POST" });
      setMsg(`Queued ${name} (task ${res.task_id})`);
    } catch (e: any) { setMsg(e.message); }
    finally { setRunning(null); }
  }
  async function runAll() {
    setRunning("ALL"); setMsg(null);
    try {
      const res = await api<{ task_id: string }>(`/feeds/run-all`, { method: "POST" });
      setMsg(`Queued all feeds (task ${res.task_id})`);
    } catch (e: any) { setMsg(e.message); }
    finally { setRunning(null); }
  }
  async function reindex() {
    setRunning("REINDEX"); setMsg(null);
    try {
      const res = await api<{ task_id: string }>(`/feeds/reindex`, { method: "POST" });
      setMsg(`Queued OpenSearch reindex (task ${res.task_id})`);
    } catch (e: any) { setMsg(e.message); }
    finally { setRunning(null); }
  }

  return (
    <>
      <Topbar title="Feeds" />
      <main className="flex-1 px-6 py-6 space-y-4">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Vulnerability data sources</CardTitle>
            <CardDescription>
              Feeds run automatically on schedule. You can trigger an immediate run here for any source.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-2">
            <Button onClick={runAll} disabled={running !== null}>
              {running === "ALL" ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />} Run all feeds
            </Button>
            <Button variant="outline" onClick={reindex} disabled={running !== null}>
              {running === "REINDEX" ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />} Reindex OpenSearch
            </Button>
            {msg && <span className="text-sm text-muted-foreground self-center ml-auto">{msg}</span>}
          </CardContent>
        </Card>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {isLoading || !data ? (
            <Card><CardContent className="p-6 text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /></CardContent></Card>
          ) : (
            data.map((f) => (
              <Card key={f.name}>
                <CardHeader>
                  <div className="flex items-center gap-2">
                    <Database className="h-4 w-4 text-primary" />
                    <CardTitle className="text-sm font-mono">{f.name}</CardTitle>
                  </div>
                  <CardDescription className="text-xs">{f.class}</CardDescription>
                </CardHeader>
                <CardContent>
                  <Button size="sm" variant="outline" onClick={() => run(f.name)} disabled={running !== null} className="w-full">
                    {running === f.name ? <Loader2 className="h-3 w-3 animate-spin" /> : <Play className="h-3 w-3" />} Run now
                  </Button>
                </CardContent>
              </Card>
            ))
          )}
        </div>
      </main>
    </>
  );
}
