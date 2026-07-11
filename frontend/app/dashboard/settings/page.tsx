"use client";

import * as React from "react";
import useSWR, { mutate } from "swr";
import { Loader2, Plus, Trash2 } from "lucide-react";
import { Topbar } from "@/components/topbar";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { SeverityBadge } from "@/components/ui/severity-badge";
import * as Dialog from "@radix-ui/react-dialog";
import { api, fetcher } from "@/lib/api";

type Rule = {
  id: string; name: string; description: string | null; enabled: boolean;
  min_severity: string; require_kev: boolean; require_exploit: boolean;
  environments: string[]; os_filter: string[]; channels: string[];
  recipients: Record<string, string>; cooldown_minutes: number;
};

export default function SettingsPage() {
  const { data: rules, isLoading } = useSWR<Rule[]>("/alert-rules", fetcher);
  const [open, setOpen] = React.useState(false);

  async function deleteRule(id: string) {
    if (!confirm("Delete this rule?")) return;
    try {
      await api(`/alert-rules/${id}`, { method: "DELETE" });
      mutate("/alert-rules");
    } catch (e: any) { alert(e.message); }
  }

  async function toggleRule(rule: Rule) {
    try {
      await api(`/alert-rules/${rule.id}`, { method: "PATCH", json: { enabled: !rule.enabled } });
      mutate("/alert-rules");
    } catch (e: any) { alert(e.message); }
  }

  return (
    <>
      <Topbar title="Settings" />
      <main className="flex-1 px-6 py-6 space-y-4">
        <div className="flex items-end justify-between">
          <div>
            <h2 className="text-lg font-semibold">Alert rules</h2>
            <p className="text-sm text-muted-foreground">When matching vulnerabilities are detected, alerts are dispatched on the configured channels.</p>
          </div>
          <Button onClick={() => setOpen(true)}><Plus className="h-4 w-4" /> New rule</Button>
        </div>

        {isLoading ? (
          <Loader2 className="h-4 w-4 animate-spin" />
        ) : (rules || []).length === 0 ? (
          <Card><CardContent className="py-12 text-center text-muted-foreground">No alert rules configured yet.</CardContent></Card>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {rules!.map((r) => (
              <Card key={r.id}>
                <CardHeader>
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <CardTitle className="text-base">{r.name}</CardTitle>
                      <CardDescription className="mt-1">{r.description || "—"}</CardDescription>
                    </div>
                    <button onClick={() => toggleRule(r)}
                      className={`text-xs rounded-md px-2 py-1 ${r.enabled ? "bg-sev-low text-white" : "bg-secondary text-muted-foreground"}`}>
                      {r.enabled ? "enabled" : "disabled"}
                    </button>
                  </div>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex flex-wrap gap-1.5 items-center text-xs">
                    <span className="text-muted-foreground">Min:</span> <SeverityBadge value={r.min_severity} />
                    {r.require_kev && <Badge variant="destructive">KEV required</Badge>}
                    {r.require_exploit && <Badge variant="destructive">Exploit required</Badge>}
                  </div>
                  <div className="text-xs">
                    <span className="text-muted-foreground">Channels:</span> {r.channels.map((c) => <Badge key={c} variant="secondary" className="ml-1">{c}</Badge>)}
                  </div>
                  {r.environments.length > 0 && (
                    <div className="text-xs"><span className="text-muted-foreground">Environments:</span> {r.environments.join(", ")}</div>
                  )}
                  {r.os_filter.length > 0 && (
                    <div className="text-xs"><span className="text-muted-foreground">OS:</span> {r.os_filter.join(", ")}</div>
                  )}
                  <div className="text-xs text-muted-foreground">Cooldown: {r.cooldown_minutes}m</div>
                  <Button variant="ghost" size="sm" className="text-destructive" onClick={() => deleteRule(r.id)}>
                    <Trash2 className="h-3 w-3" /> Delete
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </main>

      <NewRuleDialog open={open} setOpen={setOpen} />
    </>
  );
}

function NewRuleDialog({ open, setOpen }: { open: boolean; setOpen: (v: boolean) => void }) {
  const [form, setForm] = React.useState({
    name: "",
    description: "",
    min_severity: "high",
    require_kev: false,
    require_exploit: false,
    channels: ["email"] as string[],
    email: "",
    cooldown_minutes: 60,
  });
  const [submitting, setSubmitting] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  function setF<K extends keyof typeof form>(k: K, v: any) { setForm((f) => ({ ...f, [k]: v })); }
  function toggleCh(ch: string) {
    setF("channels", form.channels.includes(ch) ? form.channels.filter(c => c !== ch) : [...form.channels, ch]);
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault(); setError(null); setSubmitting(true);
    try {
      const recipients: Record<string, string> = {};
      if (form.email) recipients.email = form.email;
      await api("/alert-rules", {
        method: "POST",
        json: {
          name: form.name,
          description: form.description || null,
          enabled: true,
          min_severity: form.min_severity,
          require_kev: form.require_kev,
          require_exploit: form.require_exploit,
          environments: [],
          os_filter: [],
          channels: form.channels,
          recipients,
          cooldown_minutes: form.cooldown_minutes,
        },
      });
      mutate("/alert-rules");
      setOpen(false);
    } catch (err: any) { setError(err.message); }
    finally { setSubmitting(false); }
  }

  return (
    <Dialog.Root open={open} onOpenChange={setOpen}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm" />
        <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-full max-w-md -translate-x-1/2 -translate-y-1/2 rounded-lg border bg-card p-6 shadow-lg max-h-[85vh] overflow-y-auto">
          <Dialog.Title className="text-base font-semibold">New alert rule</Dialog.Title>
          <form onSubmit={submit} className="space-y-3 mt-3">
            <div className="space-y-1">
              <Label>Name</Label>
              <Input required value={form.name} onChange={(e) => setF("name", e.target.value)} />
            </div>
            <div className="space-y-1">
              <Label>Description</Label>
              <Input value={form.description} onChange={(e) => setF("description", e.target.value)} />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <Label>Min severity</Label>
                <select value={form.min_severity} onChange={(e) => setF("min_severity", e.target.value)}
                        className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm">
                  <option value="critical">critical</option>
                  <option value="high">high</option>
                  <option value="medium">medium</option>
                  <option value="low">low</option>
                </select>
              </div>
              <div className="space-y-1">
                <Label>Cooldown (min)</Label>
                <Input type="number" min={0} value={form.cooldown_minutes} onChange={(e) => setF("cooldown_minutes", parseInt(e.target.value) || 0)} />
              </div>
            </div>
            <div className="flex gap-3 text-sm">
              <label className="inline-flex items-center gap-2"><input type="checkbox" checked={form.require_kev} onChange={(e) => setF("require_kev", e.target.checked)} /> Require KEV</label>
              <label className="inline-flex items-center gap-2"><input type="checkbox" checked={form.require_exploit} onChange={(e) => setF("require_exploit", e.target.checked)} /> Require known exploit</label>
            </div>
            <div className="space-y-1">
              <Label>Channels</Label>
              <div className="flex flex-wrap gap-1.5">
                {["email", "telegram", "discord", "slack", "siem"].map((c) => (
                  <button key={c} type="button" onClick={() => toggleCh(c)}
                    className={`rounded-md border px-2 py-1 text-xs ${form.channels.includes(c) ? "border-primary bg-primary/10" : "border-input bg-background hover:bg-accent"}`}>
                    {c}
                  </button>
                ))}
              </div>
            </div>
            {form.channels.includes("email") && (
              <div className="space-y-1">
                <Label>Email recipient (optional)</Label>
                <Input type="email" value={form.email} onChange={(e) => setF("email", e.target.value)} placeholder="security@example.com" />
              </div>
            )}
            {error && <div className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">{error}</div>}
            <div className="flex justify-end gap-2 pt-2">
              <Button type="button" variant="ghost" onClick={() => setOpen(false)} disabled={submitting}>Cancel</Button>
              <Button type="submit" disabled={submitting}>{submitting ? <Loader2 className="h-4 w-4 animate-spin" /> : "Create"}</Button>
            </div>
          </form>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
