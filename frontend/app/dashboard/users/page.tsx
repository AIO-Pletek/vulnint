"use client";

import * as React from "react";
import useSWR, { mutate } from "swr";
import { Loader2, Plus } from "lucide-react";
import { Topbar } from "@/components/topbar";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import * as Dialog from "@radix-ui/react-dialog";
import { api, fetcher } from "@/lib/api";

type Role = { id: string; name: string; description?: string | null };
type User = {
  id: string; email: string; full_name?: string | null;
  is_active: boolean; is_superuser: boolean; is_verified: boolean;
  created_at: string; roles: Role[];
};

export default function UsersPage() {
  const { data: users, isLoading } = useSWR<User[]>("/users", fetcher);
  const { data: roles } = useSWR<Role[]>("/roles", fetcher);
  const [open, setOpen] = React.useState(false);

  return (
    <>
      <Topbar title="Users" />
      <main className="flex-1 px-6 py-6 space-y-4">
        <div className="flex justify-end">
          <Button onClick={() => setOpen(true)}><Plus className="h-4 w-4" /> New user</Button>
        </div>
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Email</TableHead>
                  <TableHead>Name</TableHead>
                  <TableHead>Roles</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {isLoading ? (
                  <TableRow><TableCell colSpan={4} className="py-8 text-center text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin inline-block" /></TableCell></TableRow>
                ) : (users || []).length === 0 ? (
                  <TableRow><TableCell colSpan={4} className="py-8 text-center text-muted-foreground">No users.</TableCell></TableRow>
                ) : (
                  users!.map((u) => (
                    <TableRow key={u.id}>
                      <TableCell className="font-mono text-sm">{u.email}</TableCell>
                      <TableCell>{u.full_name || "—"}</TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1">
                          {u.is_superuser && <Badge variant="destructive">superuser</Badge>}
                          {u.roles.map((r) => <Badge key={r.id} variant="secondary">{r.name}</Badge>)}
                        </div>
                      </TableCell>
                      <TableCell>
                        {u.is_active
                          ? <span className="text-xs text-sev-low">● active</span>
                          : <span className="text-xs text-muted-foreground">○ disabled</span>}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </main>

      <NewUserDialog open={open} setOpen={setOpen} roles={roles || []} />
    </>
  );
}

function NewUserDialog({ open, setOpen, roles }: { open: boolean; setOpen: (v: boolean) => void; roles: Role[] }) {
  const [email, setEmail] = React.useState("");
  const [name, setName] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [roleIds, setRoleIds] = React.useState<string[]>([]);
  const [submitting, setSubmitting] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault(); setError(null); setSubmitting(true);
    try {
      await api("/users", {
        method: "POST",
        json: { email, full_name: name || null, password, role_ids: roleIds },
      });
      mutate("/users");
      setOpen(false);
      setEmail(""); setName(""); setPassword(""); setRoleIds([]);
    } catch (err: any) { setError(err.message); }
    finally { setSubmitting(false); }
  }

  return (
    <Dialog.Root open={open} onOpenChange={setOpen}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm" />
        <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-full max-w-md -translate-x-1/2 -translate-y-1/2 rounded-lg border bg-card p-6 shadow-lg">
          <Dialog.Title className="text-base font-semibold">New user</Dialog.Title>
          <form onSubmit={submit} className="space-y-3 mt-3">
            <div className="space-y-1">
              <Label htmlFor="email">Email</Label>
              <Input id="email" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
            </div>
            <div className="space-y-1">
              <Label htmlFor="name">Full name</Label>
              <Input id="name" value={name} onChange={(e) => setName(e.target.value)} />
            </div>
            <div className="space-y-1">
              <Label htmlFor="pw">Initial password</Label>
              <Input id="pw" type="password" required minLength={8} value={password} onChange={(e) => setPassword(e.target.value)} />
            </div>
            <div className="space-y-1">
              <Label>Roles</Label>
              <div className="flex flex-wrap gap-1.5">
                {roles.map((r) => {
                  const active = roleIds.includes(r.id);
                  return (
                    <button key={r.id} type="button"
                      onClick={() => setRoleIds(active ? roleIds.filter(x => x !== r.id) : [...roleIds, r.id])}
                      className={`rounded-md border px-2 py-1 text-xs ${active ? "border-primary bg-primary/10" : "border-input bg-background hover:bg-accent"}`}>
                      {r.name}
                    </button>
                  );
                })}
              </div>
            </div>
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
