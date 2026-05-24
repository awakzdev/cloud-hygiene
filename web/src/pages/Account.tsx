import { useState, useEffect } from "react";
import { useSearchParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api, token } from "../api";

interface Me {
  id: string;
  email: string;
  github_id: string | null;
  totp_enabled: boolean;
  has_password: boolean;
}

export default function Account() {
  const qc = useQueryClient();
  const [params] = useSearchParams();

  const { data: me } = useQuery<Me>({
    queryKey: ["me"],
    queryFn: () => api("/v1/auth/me"),
  });

  // change password
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [pwMsg, setPwMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const changePw = useMutation({
    mutationFn: () =>
      api("/v1/auth/me/password", {
        method: "PUT",
        body: JSON.stringify(
          me?.has_password
            ? { current_password: current, new_password: next }
            : { new_password: next }
        ),
      }),
    onSuccess: () => {
      setPwMsg({ ok: true, text: me?.has_password ? "Password updated." : "Password set. You can now sign in with credentials." });
      qc.invalidateQueries({ queryKey: ["me"] });
      setCurrent(""); setNext(""); setConfirm("");
    },
    onError: (e: Error) => setPwMsg({ ok: false, text: e.message }),
  });

  function submitPassword(e: React.FormEvent) {
    e.preventDefault();
    setPwMsg(null);
    if (next !== confirm) { setPwMsg({ ok: false, text: "Passwords don't match." }); return; }
    if (next.length < 8) { setPwMsg({ ok: false, text: "At least 8 characters required." }); return; }
    changePw.mutate();
  }

  // GitHub connect/disconnect
  const [ghMsg, setGhMsg] = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    const gh = params.get("github");
    const err = params.get("error");
    if (gh === "linked") setGhMsg({ ok: true, text: "GitHub connected." });
    if (err === "github_already_linked") setGhMsg({ ok: false, text: "That GitHub account is already linked to another user." });
    if (err === "bad_link_token") setGhMsg({ ok: false, text: "Session expired. Try again." });
  }, [params]);

  const disconnectGh = useMutation({
    mutationFn: () => api("/v1/auth/me/github", { method: "DELETE" }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["me"] });
      setGhMsg({ ok: true, text: "GitHub disconnected." });
    },
    onError: (e: Error) => setGhMsg({ ok: false, text: e.message }),
  });

  const ghConnectUrl = `http://localhost:8000/v1/auth/github?link_token=${token()}`;

  return (
    <div className="max-w-lg space-y-8">
      <div>
        <h1 className="text-xl font-semibold text-zinc-900">Account</h1>
        {me && <p className="text-sm text-zinc-500 mt-1">{me.email}</p>}
      </div>

      {/* Change / set password */}
      <section className="bg-white rounded-xl border border-zinc-200 p-6">
        <h2 className="text-sm font-semibold text-zinc-900 mb-1">
          {me?.has_password ? "Change password" : "Set a password"}
        </h2>
        {!me?.has_password && (
          <p className="text-xs text-zinc-500 mb-4">
            Your account uses SSO. Set a password to also sign in with email + password.
          </p>
        )}
        <form onSubmit={submitPassword} className={`space-y-3 ${me?.has_password ? "" : "mt-4"}`}>
          {me?.has_password && (
            <div>
              <label className="block text-xs font-medium text-zinc-700 mb-1.5">Current password</label>
              <input
                type="password"
                className="w-full border border-zinc-200 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-zinc-900 focus:border-transparent transition"
                value={current}
                onChange={e => setCurrent(e.target.value)}
                required
              />
            </div>
          )}
          <div>
            <label className="block text-xs font-medium text-zinc-700 mb-1.5">New password</label>
            <input
              type="password"
              className="w-full border border-zinc-200 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-zinc-900 focus:border-transparent transition"
              value={next}
              onChange={e => setNext(e.target.value)}
              required
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-zinc-700 mb-1.5">Confirm new password</label>
            <input
              type="password"
              className="w-full border border-zinc-200 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-zinc-900 focus:border-transparent transition"
              value={confirm}
              onChange={e => setConfirm(e.target.value)}
              required
            />
          </div>
          {pwMsg && (
            <div className={`rounded-lg px-3 py-2.5 text-sm ${pwMsg.ok ? "bg-green-50 text-green-700 border border-green-200" : "bg-red-50 text-red-600 border border-red-200"}`}>
              {pwMsg.text}
            </div>
          )}
          <button
            type="submit"
            disabled={changePw.isPending}
            className="bg-zinc-900 hover:bg-zinc-800 text-white rounded-lg px-4 py-2 text-sm font-medium transition-colors disabled:opacity-60"
          >
            {changePw.isPending ? "Saving…" : me?.has_password ? "Update password" : "Set password"}
          </button>
        </form>
      </section>

      {/* GitHub */}
      <section className="bg-white rounded-xl border border-zinc-200 p-6">
        <h2 className="text-sm font-semibold text-zinc-900 mb-1">GitHub</h2>
        <p className="text-xs text-zinc-500 mb-4">Connect GitHub to sign in without a password.</p>

        {ghMsg && (
          <div className={`mb-4 rounded-lg px-3 py-2.5 text-sm ${ghMsg.ok ? "bg-green-50 text-green-700 border border-green-200" : "bg-red-50 text-red-600 border border-red-200"}`}>
            {ghMsg.text}
          </div>
        )}

        {me?.github_id ? (
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <svg className="w-5 h-5 text-zinc-600" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/>
              </svg>
              <span className="text-sm text-zinc-700">Connected</span>
            </div>
            <button
              onClick={() => disconnectGh.mutate()}
              disabled={disconnectGh.isPending}
              className="text-sm text-red-600 hover:text-red-700 font-medium transition-colors disabled:opacity-60"
            >
              {disconnectGh.isPending ? "Disconnecting…" : "Disconnect"}
            </button>
          </div>
        ) : (
          <a
            href={ghConnectUrl}
            className="inline-flex items-center gap-2 border border-zinc-200 rounded-lg px-4 py-2 text-sm font-medium text-zinc-700 hover:bg-zinc-50 transition-colors"
          >
            <svg className="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/>
            </svg>
            Connect GitHub
          </a>
        )}
      </section>

      {/* TOTP placeholder */}
      <section className="bg-white rounded-xl border border-zinc-200 p-6 opacity-60">
        <h2 className="text-sm font-semibold text-zinc-900 mb-1">Two-factor authentication</h2>
        <p className="text-xs text-zinc-500">Authenticator app (TOTP) — coming soon.</p>
      </section>
    </div>
  );
}
