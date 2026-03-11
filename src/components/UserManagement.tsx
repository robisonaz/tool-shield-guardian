import { useState, useEffect } from "react";
import { Users, Plus, Trash2, Shield, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { listUsers, createUser, updateUserRole, deleteUser } from "@/lib/api-client";
import { toast } from "sonner";

interface UserEntry {
  id: string;
  email: string;
  full_name: string;
  role: string;
  created_at: string;
}

export function UserManagement() {
  const [users, setUsers] = useState<UserEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [newEmail, setNewEmail] = useState("");
  const [newName, setNewName] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRole, setNewRole] = useState("user");
  const [creating, setCreating] = useState(false);

  const loadUsers = async () => {
    try {
      const data = await listUsers();
      setUsers(data || []);
    } catch (err: any) {
      toast.error(err.message || "Erro ao carregar usuários.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadUsers();
  }, []);

  const handleCreate = async () => {
    if (!newEmail || !newPassword || !newName) {
      toast.error("Preencha todos os campos.");
      return;
    }
    setCreating(true);
    try {
      await createUser({ email: newEmail, password: newPassword, full_name: newName, role: newRole });
      toast.success("Usuário criado com sucesso!");
      setDialogOpen(false);
      setNewEmail("");
      setNewName("");
      setNewPassword("");
      setNewRole("user");
      await loadUsers();
    } catch (err: any) {
      toast.error(err.message || "Erro ao criar usuário.");
    } finally {
      setCreating(false);
    }
  };

  const handleRoleChange = async (userId: string, role: string) => {
    try {
      await updateUserRole(userId, role);
      toast.success("Permissão atualizada!");
      await loadUsers();
    } catch (err: any) {
      toast.error(err.message || "Erro ao atualizar permissão.");
    }
  };

  const handleDelete = async (userId: string, email: string) => {
    if (!confirm(`Tem certeza que deseja remover o usuário ${email}?`)) return;
    try {
      await deleteUser(userId);
      toast.info("Usuário removido.");
      await loadUsers();
    } catch (err: any) {
      toast.error(err.message || "Erro ao remover usuário.");
    }
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Users className="h-5 w-5 text-primary" />
          <h2 className="text-lg font-sans font-semibold text-foreground">Gerenciar Usuários</h2>
        </div>
        <Button size="sm" onClick={() => setDialogOpen(true)}>
          <Plus className="h-4 w-4 mr-1" /> Novo Usuário
        </Button>
      </div>

      {loading ? (
        <div className="bg-card border border-border rounded-lg p-8 text-center">
          <p className="text-muted-foreground text-sm">Carregando usuários...</p>
        </div>
      ) : users.length === 0 ? (
        <div className="bg-card border border-border rounded-lg p-8 text-center">
          <Users className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
          <p className="text-muted-foreground text-sm">Nenhum usuário encontrado.</p>
        </div>
      ) : (
        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-secondary/30">
                <th className="text-left px-4 py-3 text-muted-foreground font-medium">Nome</th>
                <th className="text-left px-4 py-3 text-muted-foreground font-medium">E-mail</th>
                <th className="text-left px-4 py-3 text-muted-foreground font-medium">Papel</th>
                <th className="text-right px-4 py-3 text-muted-foreground font-medium">Ações</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id} className="border-b border-border/50 hover:bg-secondary/10">
                  <td className="px-4 py-3 text-foreground">
                    <div className="flex items-center gap-2">
                      {u.role === "admin" ? (
                        <ShieldCheck className="h-4 w-4 text-primary flex-shrink-0" />
                      ) : (
                        <Shield className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                      )}
                      {u.full_name || "—"}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-muted-foreground">{u.email}</td>
                  <td className="px-4 py-3">
                    <Select value={u.role} onValueChange={(v) => handleRoleChange(u.id, v)}>
                      <SelectTrigger className="w-28 h-8 text-xs">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="user">Usuário</SelectItem>
                        <SelectItem value="admin">Admin</SelectItem>
                      </SelectContent>
                    </Select>
                  </td>
                  <td className="px-4 py-3 text-right">
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => handleDelete(u.id, u.email)}
                      className="h-8 w-8"
                    >
                      <Trash2 className="h-4 w-4 text-destructive" />
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="sm:max-w-md border-border bg-card">
          <DialogHeader>
            <DialogTitle className="text-foreground">Novo Usuário</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Nome completo</Label>
              <Input value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="Nome do usuário" />
            </div>
            <div className="space-y-2">
              <Label>E-mail</Label>
              <Input value={newEmail} onChange={(e) => setNewEmail(e.target.value)} placeholder="usuario@email.com" type="email" />
            </div>
            <div className="space-y-2">
              <Label>Senha</Label>
              <Input value={newPassword} onChange={(e) => setNewPassword(e.target.value)} placeholder="••••••••" type="password" minLength={6} />
            </div>
            <div className="space-y-2">
              <Label>Papel</Label>
              <Select value={newRole} onValueChange={setNewRole}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="user">Usuário</SelectItem>
                  <SelectItem value="admin">Admin</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <Button onClick={handleCreate} disabled={creating} className="w-full">
              <Plus className="h-4 w-4 mr-2" />
              {creating ? "Criando..." : "Criar usuário"}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
