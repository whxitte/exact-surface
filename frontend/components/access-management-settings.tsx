"use client";

import { useEffect, useState } from "react";
import { ShieldCheck, Users, Trash2, Plus, Pencil, Check, X } from "lucide-react";
import { api, type Group, type Member, type PermissionInfo } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input, Label } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";

/**
 * Owner-only access control (AWS-IAM style). The owner composes permission groups
 * and assigns members to them; a member with no group has no access at all. All
 * mutations here are enforced server-side under the owner-only /members router —
 * this UI only renders for the owner and is purely a convenience over that API.
 */
export function AccessManagementSettings() {
  const [permissions, setPermissions] = useState<PermissionInfo[]>([]);
  const [groups, setGroups] = useState<Group[]>([]);
  const [members, setMembers] = useState<Member[]>([]);
  const [error, setError] = useState("");

  function load() {
    Promise.all([api.listPermissions(), api.listGroups(), api.listMembers()])
      .then(([p, g, m]) => {
        setPermissions(p);
        setGroups(g);
        setMembers(m);
      })
      .catch((e) => setError(e instanceof Error ? e.message : "failed to load"));
  }
  useEffect(load, []);

  const groupName = (id: string) => groups.find((g) => g.group_id === id)?.name ?? id;

  return (
    <div className="space-y-8">
      <PermissionGroups
        permissions={permissions}
        groups={groups}
        onChange={load}
        onError={setError}
      />
      <TeamMembers
        groups={groups}
        members={members}
        groupName={groupName}
        onChange={load}
        onError={setError}
      />
      {error && <p className="text-sm text-severity-critical">{error}</p>}
    </div>
  );
}

// -- a reusable permission picker -------------------------------------------
function PermissionPicker({
  permissions,
  selected,
  onToggle,
}: {
  permissions: PermissionInfo[];
  selected: Set<string>;
  onToggle: (key: string) => void;
}) {
  return (
    <div className="space-y-2">
      {permissions.map((p) => (
        <label
          key={p.key}
          className="flex cursor-pointer items-start gap-2.5 rounded-md border border-border p-2.5 text-sm hover:bg-muted/50"
        >
          <input
            type="checkbox"
            className="mt-0.5 h-4 w-4 accent-primary"
            checked={selected.has(p.key)}
            onChange={() => onToggle(p.key)}
          />
          <span>
            <span className="font-medium">{p.label}</span>
            <span className="block text-xs text-muted-foreground">{p.description}</span>
          </span>
        </label>
      ))}
    </div>
  );
}

// -- permission groups -------------------------------------------------------
function PermissionGroups({
  permissions,
  groups,
  onChange,
  onError,
}: {
  permissions: PermissionInfo[];
  groups: Group[];
  onChange: () => void;
  onError: (m: string) => void;
}) {
  const [newName, setNewName] = useState("");
  const [newPerms, setNewPerms] = useState<Set<string>>(new Set(["view"]));
  const [editing, setEditing] = useState<string | null>(null);
  const [editName, setEditName] = useState("");
  const [editPerms, setEditPerms] = useState<Set<string>>(new Set());

  const toggle = (set: Set<string>, key: string) => {
    const next = new Set(set);
    next.has(key) ? next.delete(key) : next.add(key);
    return next;
  };

  async function create(e: React.FormEvent) {
    e.preventDefault();
    onError("");
    try {
      await api.createGroup(newName.trim(), [...newPerms]);
      setNewName("");
      setNewPerms(new Set(["view"]));
      onChange();
    } catch (err) {
      onError(err instanceof Error ? err.message : "failed");
    }
  }

  function startEdit(g: Group) {
    setEditing(g.group_id);
    setEditName(g.name);
    setEditPerms(new Set(g.permissions));
  }

  async function saveEdit(id: string) {
    onError("");
    try {
      await api.updateGroup(id, { name: editName.trim(), permissions: [...editPerms] });
      setEditing(null);
      onChange();
    } catch (err) {
      onError(err instanceof Error ? err.message : "failed");
    }
  }

  async function remove(g: Group) {
    onError("");
    try {
      await api.deleteGroup(g.group_id);
      onChange();
    } catch (err) {
      onError(err instanceof Error ? err.message : "failed");
    }
  }

  return (
    <Card>
      <CardContent className="space-y-4 p-5">
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-primary" />
          <h2 className="text-sm font-semibold">Permission groups</h2>
        </div>
        <p className="text-xs text-muted-foreground">
          Compose a set of permissions, then add teammates to it. A member with no group
          has no access. A “manage” permission includes viewing that area.
        </p>

        <div className="space-y-2">
          {groups.map((g) =>
            editing === g.group_id ? (
              <div key={g.group_id} className="space-y-3 rounded-md border border-primary/40 p-3">
                <Input value={editName} onChange={(e) => setEditName(e.target.value)} />
                <PermissionPicker
                  permissions={permissions}
                  selected={editPerms}
                  onToggle={(k) => setEditPerms((s) => toggle(s, k))}
                />
                <div className="flex justify-end gap-2">
                  <Button variant="outline" size="sm" onClick={() => setEditing(null)}>
                    <X className="h-4 w-4" /> Cancel
                  </Button>
                  <Button size="sm" onClick={() => saveEdit(g.group_id)}>
                    <Check className="h-4 w-4" /> Save
                  </Button>
                </div>
              </div>
            ) : (
              <div
                key={g.group_id}
                className="flex items-center gap-3 rounded-md border border-border px-3 py-2 text-sm"
              >
                <span className="font-medium">{g.name}</span>
                {g.is_default && (
                  <span className="rounded-full bg-muted px-2 py-0.5 text-[10px] uppercase tracking-wide text-muted-foreground">
                    default
                  </span>
                )}
                <div className="flex flex-1 flex-wrap gap-1">
                  {g.permissions.length === 0 && (
                    <span className="text-xs text-muted-foreground">no permissions</span>
                  )}
                  {g.permissions.map((p) => (
                    <Badge key={p} className="border-primary/30 bg-primary/10 text-primary">
                      {p}
                    </Badge>
                  ))}
                </div>
                <button
                  onClick={() => startEdit(g)}
                  className="text-muted-foreground hover:text-foreground"
                  title="Edit"
                >
                  <Pencil className="h-4 w-4" />
                </button>
                {!g.is_default && (
                  <button
                    onClick={() => remove(g)}
                    className="text-muted-foreground hover:text-severity-critical"
                    title="Delete"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                )}
              </div>
            ),
          )}
        </div>

        <form onSubmit={create} className="space-y-3 rounded-md border border-dashed border-border p-3">
          <div className="space-y-1.5">
            <Label>New group name</Label>
            <Input
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="Analysts"
              required
            />
          </div>
          <PermissionPicker
            permissions={permissions}
            selected={newPerms}
            onToggle={(k) => setNewPerms((s) => toggle(s, k))}
          />
          <div className="flex justify-end">
            <Button type="submit" size="sm">
              <Plus className="h-4 w-4" /> Create group
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

// -- team members ------------------------------------------------------------
function TeamMembers({
  groups,
  members,
  groupName,
  onChange,
  onError,
}: {
  groups: Group[];
  members: Member[];
  groupName: (id: string) => string;
  onChange: () => void;
  onError: (m: string) => void;
}) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [newGroups, setNewGroups] = useState<Set<string>>(new Set());

  const toggleGroup = (set: Set<string>, id: string) => {
    const next = new Set(set);
    next.has(id) ? next.delete(id) : next.add(id);
    return next;
  };

  async function invite(e: React.FormEvent) {
    e.preventDefault();
    onError("");
    try {
      await api.createMember(email.trim(), password, [...newGroups]);
      setEmail("");
      setPassword("");
      setNewGroups(new Set());
      onChange();
    } catch (err) {
      onError(err instanceof Error ? err.message : "failed");
    }
  }

  async function setGroups(member: Member, ids: string[]) {
    onError("");
    try {
      await api.setMemberGroups(member.user_id, ids);
      onChange();
    } catch (err) {
      onError(err instanceof Error ? err.message : "failed");
    }
  }

  async function remove(member: Member) {
    onError("");
    try {
      await api.deleteMember(member.user_id);
      onChange();
    } catch (err) {
      onError(err instanceof Error ? err.message : "failed");
    }
  }

  return (
    <Card>
      <CardContent className="space-y-4 p-5">
        <div className="flex items-center gap-2">
          <Users className="h-4 w-4 text-primary" />
          <h2 className="text-sm font-semibold">Team members</h2>
        </div>

        <div className="space-y-2">
          {members.map((m) => {
            const isOwner = m.role === "owner";
            const assigned = new Set(m.group_ids);
            return (
              <div key={m.user_id} className="rounded-md border border-border px-3 py-2.5 text-sm">
                <div className="flex items-center gap-3">
                  <span className="flex-1 font-medium">{m.email ?? m.user_id}</span>
                  <span
                    className={`rounded-full px-2 py-0.5 text-[10px] uppercase tracking-wide ${
                      isOwner ? "bg-primary/10 text-primary" : "bg-muted text-muted-foreground"
                    }`}
                  >
                    {m.role}
                  </span>
                  {!m.email_verified && !isOwner && (
                    <span className="text-[10px] text-severity-medium">unverified</span>
                  )}
                  {!isOwner && (
                    <button
                      onClick={() => remove(m)}
                      className="text-muted-foreground hover:text-severity-critical"
                      title="Remove member"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  )}
                </div>
                {isOwner ? (
                  <p className="mt-1 text-xs text-muted-foreground">
                    The owner holds every permission and can’t be changed.
                  </p>
                ) : (
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {groups.length === 0 && (
                      <span className="text-xs text-muted-foreground">create a group first</span>
                    )}
                    {groups.map((g) => {
                      const on = assigned.has(g.group_id);
                      return (
                        <button
                          key={g.group_id}
                          onClick={() =>
                            setGroups(m, [...toggleGroup(assigned, g.group_id)])
                          }
                          className={`rounded-full border px-2.5 py-0.5 text-xs transition-colors ${
                            on
                              ? "border-primary/40 bg-primary/10 text-primary"
                              : "border-border text-muted-foreground hover:bg-muted/50"
                          }`}
                        >
                          {groupName(g.group_id)}
                        </button>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        <form onSubmit={invite} className="space-y-3 rounded-md border border-dashed border-border p-3">
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label>Email</Label>
              <Input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="teammate@company.com"
                required
              />
            </div>
            <div className="space-y-1.5">
              <Label>Temporary password</Label>
              <Input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="at least 8 characters"
                minLength={8}
                required
              />
            </div>
          </div>
          {groups.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {groups.map((g) => {
                const on = newGroups.has(g.group_id);
                return (
                  <button
                    type="button"
                    key={g.group_id}
                    onClick={() => setNewGroups((s) => toggleGroup(s, g.group_id))}
                    className={`rounded-full border px-2.5 py-0.5 text-xs transition-colors ${
                      on
                        ? "border-primary/40 bg-primary/10 text-primary"
                        : "border-border text-muted-foreground hover:bg-muted/50"
                    }`}
                  >
                    {g.name}
                  </button>
                );
              })}
            </div>
          )}
          <div className="flex items-center justify-between">
            <p className="text-xs text-muted-foreground">
              They can sign in immediately with this password and only see what their groups allow.
            </p>
            <Button type="submit" size="sm">
              <Plus className="h-4 w-4" /> Add member
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}
