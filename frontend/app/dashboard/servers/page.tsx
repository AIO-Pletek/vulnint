"use client";

import * as React from "react";
import Link from "next/link";
import useSWR, { mutate } from "swr";
import { Plus, Loader2, Copy, Check, Search, Download } from "lucide-react";
import { Topbar } from "@/components/topbar";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import * as Dialog from "@radix-ui/react-dialog";
import { api, fetcher } from "@/lib/api";
import { formatRelative } from "@/lib/utils";

type Server = {
  id: string; hostname: string; ip_address?: string; environment: string;
  os_family: string | null; os_version: string | null; kernel: string | null;
  cpanel_version: string | null; tags: string[]; is_active: boolean;
  last_seen_at: string | null; created_at: string;
};
type ServerPage = { items: Server[]; total: number; page: number; page_size: number };

export default function ServersPage() {
  const [q, setQ] = React.useState("");
  const [debounced, setDebounced] = React.useState("");
  const [open, setOpen] = React.useState(false);
  const [downloadOpen, setDownloadOpen] = React.useState(false);
  const [token, setToken] = React.useState<{ id: string; hostname: string; api_token: string } | null>(null);

  React.useEffect(() => {
    const t = setTimeout(() => setDebounced(q), 250);
    return () => clearTimeout(t);
  }, [q]);

  const params = new URLSearchParams({ page_size: "50" });
  if (debounced) params.set("q", debounced);
  const { data, isLoading } = useSWR<ServerPage>(`/servers?${params.toString()}`, fetcher);

  return (
    <>
      <Topbar title="Servers" />
      <main className="flex-1 px-6 py-6 space-y-4">
        <div className="flex items-center justify-between gap-3">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input placeholder="Search hostname or IP…" value={q} onChange={(e) => setQ(e.target.value)} className="pl-9" />
          </div>
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => setDownloadOpen(true)}>
              <Download className="h-4 w-4" /> Agent
            </Button>
            <Button onClick={() => setOpen(true)}>
              <Plus className="h-4 w-4" /> Add server
            </Button>
          </div>
        </div>

        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Hostname</TableHead>
                  <TableHead>OS</TableHead>
                  <TableHead>Env</TableHead>
                  <TableHead>Kernel</TableHead>
                  <TableHead>cPanel</TableHead>
                  <TableHead>Last seen</TableHead>
                  <TableHead></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {isLoading && !data ? (
                  <TableRow><TableCell colSpan={7} className="py-10 text-center text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin inline-block" /> Loading…</TableCell></TableRow>
                ) : (data?.items || []).length === 0 ? (
                  <TableRow><TableCell colSpan={7} className="py-10 text-center text-muted-foreground">No servers yet.</TableCell></TableRow>
                ) : (
                  data!.items.map((s) => (
                    <TableRow key={s.id} className="cursor-pointer">
                      <TableCell>
                        <Link href={`/dashboard/servers/${s.id}`} className="text-primary hover:underline font-medium text-sm">
                          {s.hostname}
                        </Link>
                        {s.ip_address && <div className="text-xs text-muted-foreground font-mono">{s.ip_address}</div>}
                      </TableCell>
                      <TableCell className="text-sm">
                        {(s.os_family || "?").toUpperCase()} <span className="text-muted-foreground">{s.os_version || ""}</span>
                      </TableCell>
                      <TableCell>
                        <Badge variant={s.environment === "production" ? "destructive" : "secondary"}>{s.environment}</Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs">{s.kernel || "—"}</TableCell>
                      <TableCell className="font-mono text-xs">{s.cpanel_version || "—"}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{formatRelative(s.last_seen_at)}</TableCell>
                      <TableCell>
                        {s.is_active
                          ? <span className="text-xs text-sev-low">●</span>
                          : <span className="text-xs text-muted-foreground">○</span>}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </main>

      <NewServerDialog open={open} setOpen={setOpen} onCreated={(srv) => { setToken(srv); mutate((k: any) => typeof k === "string" && k.startsWith("/servers"), undefined, { revalidate: true }); }} />
      <TokenDialog token={token} setToken={setToken} />
      <AgentDownloadDialog open={downloadOpen} setOpen={setDownloadOpen} />
    </>
  );
}

function NewServerDialog({ open, setOpen, onCreated }: {
  open: boolean; setOpen: (v: boolean) => void;
  onCreated: (s: { id: string; hostname: string; api_token: string }) => void;
}) {
  const [hostname, setHostname] = React.useState("");
  const [ip, setIp] = React.useState("");
  const [env, setEnv] = React.useState("production");
  const [osFamily, setOsFamily] = React.useState("ubuntu");
  const [submitting, setSubmitting] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const created = await api<{ id: string; hostname: string; api_token: string }>("/servers", {
        method: "POST",
        json: { hostname, ip_address: ip || null, environment: env, os_family: osFamily, tags: [] },
      });
      setOpen(false);
      onCreated(created);
      setHostname(""); setIp(""); setEnv("production"); setOsFamily("ubuntu");
    } catch (err: any) {
      setError(err.message || "Failed");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Dialog.Root open={open} onOpenChange={setOpen}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm" />
        <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-full max-w-md -translate-x-1/2 -translate-y-1/2 rounded-lg border bg-card p-6 shadow-lg">
          <Dialog.Title className="text-base font-semibold">Add server</Dialog.Title>
          <Dialog.Description className="text-sm text-muted-foreground mb-4">
            An agent token will be issued — copy it once, it can&apos;t be retrieved later.
          </Dialog.Description>
          <form onSubmit={submit} className="space-y-3">
            <div className="space-y-1">
              <Label htmlFor="hostname">Hostname *</Label>
              <Input id="hostname" required value={hostname} onChange={(e) => setHostname(e.target.value)} placeholder="web-01.example.com" />
            </div>
            <div className="space-y-1">
              <Label htmlFor="ip">IP address</Label>
              <Input id="ip" value={ip} onChange={(e) => setIp(e.target.value)} placeholder="10.0.0.1" />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <Label htmlFor="env">Environment</Label>
                <select id="env" value={env} onChange={(e) => setEnv(e.target.value)}
                        className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm">
                  <option value="production">production</option>
                  <option value="staging">staging</option>
                  <option value="development">development</option>
                </select>
              </div>
              <div className="space-y-1">
                <Label htmlFor="os">OS family</Label>
                <select id="os" value={osFamily} onChange={(e) => setOsFamily(e.target.value)}
                        className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm">
                  <option value="ubuntu">ubuntu</option>
                  <option value="debian">debian</option>
                  <option value="almalinux">almalinux</option>
                  <option value="rocky">rocky</option>
                  <option value="cloudlinux">cloudlinux</option>
                  <option value="windows">windows</option>
                  <option value="other">other</option>
                </select>
              </div>
            </div>
            {error && <div className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">{error}</div>}
            <div className="flex justify-end gap-2 pt-2">
              <Button type="button" variant="ghost" onClick={() => setOpen(false)} disabled={submitting}>Cancel</Button>
              <Button type="submit" disabled={submitting}>
                {submitting ? <Loader2 className="h-4 w-4 animate-spin" /> : "Create"}
              </Button>
            </div>
          </form>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function TokenDialog({ token, setToken }: { token: any; setToken: (v: any) => void }) {
  const [copied, setCopied] = React.useState(false);
  if (!token) return null;
  return (
    <Dialog.Root open={!!token} onOpenChange={() => setToken(null)}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm" />
        <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-full max-w-lg -translate-x-1/2 -translate-y-1/2 rounded-lg border bg-card p-6 shadow-lg">
          <Dialog.Title className="text-base font-semibold">Agent token issued</Dialog.Title>
          <Dialog.Description className="text-sm text-muted-foreground mb-4">
            Save this token — it cannot be retrieved later. Use it on <span className="font-mono">{token.hostname}</span>.
          </Dialog.Description>
          <div className="rounded-md bg-muted p-3 font-mono text-xs break-all border">{token.api_token}</div>
          <div className="flex justify-end gap-2 mt-4">
            <Button variant="outline" size="sm" onClick={() => {
              navigator.clipboard.writeText(token.api_token);
              setCopied(true);
              setTimeout(() => setCopied(false), 1500);
            }}>
              {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
              {copied ? "Copied" : "Copy"}
            </Button>
            <Button onClick={() => setToken(null)}>Done</Button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function AgentDownloadDialog({ open, setOpen }: { open: boolean; setOpen: (v: boolean) => void }) {
  const [os, setOs] = React.useState<"linux" | "windows">("linux");
  const [copiedCmd, setCopiedCmd] = React.useState(false);
  const [copiedWget, setCopiedWget] = React.useState(false);

  const apiBase = typeof window !== "undefined" ? `${window.location.protocol}//${window.location.host}` : "";

  const commands: Record<string, { label: string; desc: string; cmd: string; wget: string; wgetLabel: string }> = {
    linux: {
      label: "Linux",
      desc: "Ubuntu, Debian, AlmaLinux, Rocky, CloudLinux",
      cmd: `curl -fsS ${apiBase}/api/v1/agents/linux/install | sudo bash -s -- ${apiBase} <AGENT_TOKEN>`,
      wget: `wget ${apiBase}/api/v1/agents/linux/install -O install.sh && sudo bash install.sh ${apiBase} <AGENT_TOKEN>`,
      wgetLabel: "Atau download lalu jalanin manual:",
    },
    windows: {
      label: "Windows",
      desc: "Windows Server 2016+ (PowerShell 5.1+)",
      cmd: `[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-Expression (Invoke-WebRequest -Uri "${apiBase}/api/v1/agents/windows/install" -UseBasicParsing).Content; Install-Agent -ApiUrl "${apiBase}" -AgentToken "<AGENT_TOKEN>"`,
      wget: `Invoke-WebRequest -Uri "${apiBase}/api/v1/agents/windows/install" -OutFile "Install-Agent.ps1"; .\\Install-Agent.ps1 -ApiUrl "${apiBase}" -AgentToken "<AGENT_TOKEN>"`,
      wgetLabel: "Atau download lalu jalanin manual (elevated PowerShell):",
    },
  };

  const current = commands[os];

  return (
    <Dialog.Root open={open} onOpenChange={setOpen}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm" />
        <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-full max-w-xl -translate-x-1/2 -translate-y-1/2 rounded-lg border bg-card p-6 shadow-lg max-h-[90vh] overflow-y-auto">
          <Dialog.Title className="text-base font-semibold">Download agent installer</Dialog.Title>
          <Dialog.Description className="text-sm text-muted-foreground mb-4">
            Jalankan perintah ini di server target. Ganti <code className="bg-muted px-1 rounded text-xs font-mono">&lt;AGENT_TOKEN&gt;</code> dengan token yang didapat saat menambahkan server.
          </Dialog.Description>

          {/* OS tabs */}
          <div className="flex gap-1 mb-4 bg-muted rounded-md p-1">
            {(["linux", "windows"] as const).map((t) => (
              <button
                key={t}
                onClick={() => setOs(t)}
                className={`flex-1 text-sm rounded-sm py-1.5 font-medium transition-colors ${
                  os === t ? "bg-background shadow-sm text-foreground" : "text-muted-foreground hover:text-foreground"
                }`}
              >
                {commands[t].label}
              </button>
            ))}
          </div>

          <p className="text-xs text-muted-foreground mb-2">{current.desc}</p>

          {/* One-liner command */}
          <div className="space-y-1.5">
            <Label>Quick install (copy-paste)</Label>
            <div className="relative">
              <pre className="bg-muted rounded-md p-3 pr-12 text-xs font-mono break-all whitespace-pre-wrap overflow-x-auto max-h-32 overflow-y-auto">
                {current.cmd}
              </pre>
              <Button
                variant="ghost"
                size="sm"
                className="absolute top-2 right-2"
                onClick={() => { navigator.clipboard.writeText(current.cmd); setCopiedCmd(true); setTimeout(() => setCopiedCmd(false), 1500); }}
              >
                {copiedCmd ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
              </Button>
            </div>
          </div>

          {/* Wget / manual download */}
          <div className="space-y-1.5 mt-3">
            <Label className="text-xs text-muted-foreground">{current.wgetLabel}</Label>
            <div className="relative">
              <pre className="bg-muted rounded-md p-3 pr-12 text-xs font-mono break-all whitespace-pre-wrap overflow-x-auto max-h-24 overflow-y-auto">
                {current.wget}
              </pre>
              <Button
                variant="ghost"
                size="sm"
                className="absolute top-2 right-2"
                onClick={() => { navigator.clipboard.writeText(current.wget); setCopiedWget(true); setTimeout(() => setCopiedWget(false), 1500); }}
              >
                {copiedWget ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
              </Button>
            </div>
          </div>

          {/* Direct download links */}
          <div className="mt-4 pt-3 border-t text-xs text-muted-foreground space-y-1">
            <div className="font-medium text-foreground text-sm mb-1">Direct download links:</div>
            <a href={`/api/v1/agents/${os}/install`} className="text-primary hover:underline block" target="_blank">
              📥 {os === "linux" ? "install.sh" : "Install-Agent.ps1"} (installer)
            </a>
            <a href={`/api/v1/agents/${os}/agent`} className="text-primary hover:underline block" target="_blank">
              📄 {os === "linux" ? "vulnint-agent.py" : "vulnint-agent.ps1"} (agent script)
            </a>
          </div>

          <div className="flex justify-end mt-4">
            <Button variant="ghost" onClick={() => setOpen(false)}>Close</Button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
