import { useState, useEffect } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { api, BASE, formatApiError, storeTokens } from "../api";

interface LoginResponse {
  access_token?: string | null;
  refresh_token?: string | null;
  org_id?: string | null;
  mfa_required?: boolean;
  mfa_token?: string | null;
}

const MFA_STORAGE_KEY = "vigil_mfa_token";

function oauthErrorMessage(code: string): string {
  switch (code) {
    case "oauth_denied":
      return "Sign-in cancelled.";
    case "no_email":
      return "Could not read your email from the provider — check account settings.";
    case "bad_link_token":
      return "Session expired while connecting. Sign in and try again.";
    case "github_already_linked":
      return "That GitHub account is already linked to another user.";
    case "gitlab_already_linked":
      return "That GitLab account is already linked to another user.";
    case "google_already_linked":
      return "That Google account is already linked to another user.";
    case "no_account_for_idp":
      return "No account matches that sign-in. Sign up first, then connect this provider.";
    case "server_error":
      return "Sign-in failed on our side. Try again.";
    default:
      return "Sign-in failed. Try again.";
  }
}

function storeMfaToken(token: string) {
  sessionStorage.setItem(MFA_STORAGE_KEY, token);
}

function clearMfaToken() {
  sessionStorage.removeItem(MFA_STORAGE_KEY);
}

function readStoredMfaToken(): string | null {
  return sessionStorage.getItem(MFA_STORAGE_KEY);
}

const CONTROL_STATUS_MOCK = (
  <div className="mt-1.5 space-y-1 rounded-lg border border-white/10 bg-black/20 p-2">
    {[
      { id: "CC6.1", status: "Pass", tone: "text-emerald-400 bg-emerald-500/15" },
      { id: "CC6.3", status: "Review", tone: "text-amber-400 bg-amber-500/15" },
      { id: "CC7.2", status: "Review", tone: "text-amber-400 bg-amber-500/15" },
    ].map((row) => (
      <div key={row.id} className="flex items-center justify-between gap-2 text-[10px]">
        <span className="font-mono text-zinc-300">{row.id}</span>
        <span className={`rounded px-1.5 py-0.5 text-[9px] font-medium ${row.tone}`}>{row.status}</span>
      </div>
    ))}
  </div>
);

const TIMELINE_EXCEPTIONS_MOCK = (
  <div className="mt-1.5 space-y-1.5 rounded-lg border border-white/10 bg-black/20 p-2">
    {[
      { time: "Apr 18", event: "Finding opened · IAM wildcard" },
      { time: "May 02", event: "Exception approved until Q3" },
    ].map((row) => (
      <div key={row.time} className="flex gap-2 text-[10px]">
        <span className="shrink-0 font-mono text-zinc-500">{row.time}</span>
        <span className="text-zinc-300">{row.event}</span>
      </div>
    ))}
    <div className="rounded border border-amber-500/15 bg-amber-500/5 px-2 py-1.5 text-[10px] text-amber-100/80">
      CC6.6 exception · approver on file until Aug 2026
    </div>
  </div>
);

function LoginBrand({ compact = false }: { compact?: boolean }) {
  return (
    <div className={`flex items-center gap-2.5 ${compact ? "mb-6" : "mb-8 lg:mb-10"}`}>
      <img
        src="/favicon.png"
        alt="Vigil"
        className={compact ? "w-10 h-10 object-contain" : "w-11 h-11 object-contain lg:w-12 lg:h-12"}
      />
      <span className="text-white text-lg font-semibold tracking-tight lg:text-xl">Vigil</span>
    </div>
  );
}

function SampleEvidencePanel({
  loading,
  error,
  onDownload,
  compact = false,
}: {
  loading: boolean;
  error: string | null;
  onDownload: () => void;
  compact?: boolean;
}) {
  if (compact) {
    return (
      <div className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
        <p className="text-sm font-medium text-zinc-200">Sample SOC 2 evidence pack</p>
        <p className="mt-1 text-xs leading-relaxed text-zinc-500">
          Preview control status, timeline, and exceptions before you sign in.
        </p>
        {error && (
          <p className="mt-2 text-xs text-red-400">{error}</p>
        )}
        <button
          type="button"
          onClick={onDownload}
          disabled={loading}
          className="mt-3 inline-flex w-full items-center justify-center gap-1.5 rounded-lg border border-indigo-400/30 bg-transparent px-3 py-2 text-xs font-medium text-indigo-200/90 transition hover:border-indigo-400/50 hover:bg-indigo-500/5 disabled:opacity-60"
        >
          {loading ? "Preparing…" : "Preview sample evidence pack"}
        </button>
      </div>
    );
  }

  return (
    <div className="relative overflow-hidden rounded-xl border border-white/10 bg-white/[0.03] p-4 shadow-lg shadow-black/20 backdrop-blur-sm lg:p-5">
      <div className="relative">
        <p className="text-[10px] font-medium uppercase tracking-wide text-zinc-500">Product preview</p>
        <h2 className="mt-1 text-base font-semibold tracking-tight text-zinc-100">
          See what Vigil generates
        </h2>
        <p className="mt-1 text-xs leading-relaxed text-zinc-500">
          Sample SOC 2 pack with control status, timeline, exceptions, and evidence references.
        </p>

        <div className="mt-3 space-y-2.5">
          <div className="rounded-lg border border-white/10 bg-black/15 p-2.5">
            <p className="text-xs font-medium text-zinc-200">Control status summary</p>
            {CONTROL_STATUS_MOCK}
          </div>
          <div className="rounded-lg border border-white/10 bg-black/15 p-2.5">
            <p className="text-xs font-medium text-zinc-200">Timeline and exceptions</p>
            {TIMELINE_EXCEPTIONS_MOCK}
          </div>
        </div>

        {error && (
          <div className="mt-2.5 rounded-lg border border-red-500/25 bg-red-500/10 px-2.5 py-2 text-xs text-red-300">
            {error}
          </div>
        )}

        <button
          type="button"
          onClick={onDownload}
          disabled={loading}
          className="mt-3 inline-flex w-full items-center justify-center gap-1.5 rounded-lg border border-indigo-400/35 bg-indigo-500/5 px-3 py-2 text-xs font-medium text-indigo-200 transition hover:border-indigo-400/55 hover:bg-indigo-500/10 disabled:opacity-60"
        >
          <svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true">
            <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M7.5 10.5L12 15m0 0l4.5-4.5M12 15V3" />
          </svg>
          {loading ? "Preparing…" : "Preview sample evidence pack"}
        </button>

        <p className="mt-2 text-center text-[10px] text-zinc-600">No account required · synthetic demo data</p>
      </div>
    </div>
  );
}

export default function Login() {
  const nav = useNavigate();
  const [params, setParams] = useSearchParams();
  const [mode, setMode] = useState<"login" | "signup">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [orgName, setOrgName] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [sampleLoading, setSampleLoading] = useState(false);
  const [sampleError, setSampleError] = useState<string | null>(null);

  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [mfaCode, setMfaCode] = useState("");

  useEffect(() => {
    const token = params.get("mfa_token");
    const oauthErr = params.get("error");
    const next = new URLSearchParams(params);

    if (token) {
      beginMfa(token);
      next.delete("mfa_token");
      next.delete("error");
      setParams(next, { replace: true });
      return;
    }

    if (oauthErr) {
      setErr(oauthErrorMessage(oauthErr));
      next.delete("error");
      setParams(next, { replace: true });
      exitMfa();
      return;
    }

    const stored = readStoredMfaToken();
    if (stored) {
      setMfaToken(stored);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps -- run when URL search params change
  }, [params]);

  function beginMfa(token: string) {
    setMfaToken(token);
    storeMfaToken(token);
    setErr(null);
    setMfaCode("");
  }

  function exitMfa() {
    setMfaToken(null);
    clearMfaToken();
    setMfaCode("");
    setErr(null);
  }

  async function completeLogin(res: LoginResponse) {
    if (res.mfa_required && res.mfa_token) {
      beginMfa(res.mfa_token);
      return;
    }
    if (!res.access_token) {
      throw new Error("missing access token");
    }
    clearMfaToken();
    storeTokens(res.access_token, res.refresh_token ?? "");
    nav("/findings");
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    setPasswordError(null);
    if (!email.trim()) {
      setErr("Enter your email address.");
      return;
    }
    if (!password) {
      setPasswordError("Enter your password.");
      return;
    }
    if (mode === "signup" && password.length < 12) {
      setPasswordError("Password must be at least 12 characters.");
      return;
    }
    if (mode === "signup" && !orgName.trim()) {
      setErr("Enter your organization name.");
      return;
    }
    setLoading(true);
    try {
      const path = mode === "login" ? "/v1/auth/login" : "/v1/auth/signup";
      const body = mode === "login" ? { email, password } : { email, password, org_name: orgName };
      const res = await api<LoginResponse>(path, { method: "POST", body: JSON.stringify(body) });
      await completeLogin(res);
    } catch (e) {
      setErr(formatApiError(e));
    } finally {
      setLoading(false);
    }
  }

  async function submitMfa(e: React.FormEvent) {
    e.preventDefault();
    if (!mfaToken) return;
    setErr(null);
    setLoading(true);
    try {
      const res = await api<{ access_token: string; refresh_token: string }>("/v1/auth/mfa/verify", {
        method: "POST",
        body: JSON.stringify({ mfa_token: mfaToken, code: mfaCode }),
      });
      clearMfaToken();
      storeTokens(res.access_token, res.refresh_token);
      nav("/findings");
    } catch (e) {
      const msg = formatApiError(e);
      if (/expired|sign in again/i.test(msg)) {
        exitMfa();
      } else if (/too many failed attempts|try again in/i.test(msg)) {
        exitMfa();
      }
      setErr(msg);
      setMfaCode("");
    } finally {
      setLoading(false);
    }
  }

  async function downloadSamplePack() {
    setSampleLoading(true);
    setSampleError(null);
    try {
      const res = await fetch(`${BASE}/v1/exports/sample-evidence-pack?framework=soc2`);
      if (!res.ok) throw new Error("Download failed");
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `vigil-sample-soc-2-${new Date().toISOString().slice(0, 10)}.zip`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch {
      setSampleError("Could not download sample pack. Try again.");
    } finally {
      setSampleLoading(false);
    }
  }

  if (mfaToken) {
    return (
      <div className="min-h-screen bg-zinc-900 flex items-center justify-center p-4">
        <div className="w-full max-w-sm">
          <div className="flex items-center justify-center gap-3 mb-8">
            <img src="/favicon.png" alt="Vigil" className="w-16 h-16 object-contain" />
            <span className="text-white text-xl font-semibold tracking-tight">Vigil</span>
          </div>

          <div className="bg-white rounded-2xl shadow-2xl p-8">
            <h1 className="text-lg font-semibold text-zinc-900 mb-1">Two-factor authentication</h1>
            <p className="text-sm text-zinc-500 mb-6">
              Enter the 6-digit code from your authenticator app.
            </p>

            <form onSubmit={submitMfa} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-zinc-700 mb-1.5">Authentication code</label>
                <input
                  className="w-full border border-zinc-200 rounded-lg px-3 py-2.5 text-sm tracking-[0.3em] text-center font-mono focus:outline-none focus:ring-2 focus:ring-zinc-900 focus:border-transparent transition"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  placeholder="000000"
                  maxLength={6}
                  value={mfaCode}
                  onChange={e => setMfaCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                  required
                  autoFocus
                />
              </div>

              {err && (
                <div className="bg-red-50 border border-red-200 rounded-lg px-3 py-2.5 text-sm text-red-600">
                  {err}
                </div>
              )}

              <button
                className="w-full bg-zinc-900 hover:bg-zinc-800 text-white rounded-lg py-2.5 text-sm font-medium transition-colors disabled:opacity-60"
                disabled={loading || mfaCode.length !== 6}
              >
                {loading ? "Verifying…" : "Continue"}
              </button>
            </form>

            <button
              type="button"
              className="mt-4 w-full text-sm text-zinc-500 hover:text-zinc-700 transition-colors"
              onClick={exitMfa}
            >
              Back to sign in
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-zinc-900 flex items-center justify-center p-4 lg:p-8">
      <div className="w-full max-w-4xl">
        <LoginBrand />

        <div className="grid items-start gap-6 lg:grid-cols-[minmax(0,1.15fr)_minmax(0,0.82fr)] lg:gap-7">
          {/* Login — primary surface */}
          <div className="w-full max-w-md mx-auto lg:mx-0 lg:max-w-none">
            <div className="rounded-2xl bg-white p-8 shadow-2xl shadow-black/25 ring-1 ring-white/10">
              <h1 className="text-lg font-semibold text-zinc-900 mb-1">
                {mode === "login" ? "Welcome back" : "Create your account"}
              </h1>
              <p className="text-sm text-zinc-500 mb-6">
                {mode === "login" ? "Sign in to your workspace" : "Start monitoring your AWS IAM posture"}
              </p>

              <form noValidate onSubmit={submit} className="space-y-4">
            {mode === "signup" && (
              <div>
                <label className="block text-xs font-medium text-zinc-700 mb-1.5">Organization name</label>
                <input
                  className="w-full border border-zinc-200 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-zinc-900 focus:border-transparent transition"
                  placeholder=""
                  value={orgName}
                  onChange={e => setOrgName(e.target.value)}
                  required
                />
              </div>
            )}
            <div>
              <label className="block text-xs font-medium text-zinc-700 mb-1.5">Email</label>
              <input
                className="w-full border border-zinc-200 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-zinc-900 focus:border-transparent transition"
                type="email"
                placeholder="Email address"
                value={email}
                onChange={e => setEmail(e.target.value)}
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-zinc-700 mb-1.5">Password</label>
              <input
                className={`w-full rounded-lg border px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:border-transparent transition ${
                  passwordError
                    ? "border-red-300 focus:ring-red-500"
                    : "border-zinc-200 focus:ring-zinc-900"
                }`}
                type="password"
                placeholder="••••••••"
                value={password}
                onChange={e => { setPassword(e.target.value); setPasswordError(null); }}
              />
              {passwordError ? (
                <p className="mt-1.5 text-xs text-red-600">{passwordError}</p>
              ) : mode === "signup" ? (
                <p className="mt-1.5 text-xs text-zinc-400">At least 12 characters.</p>
              ) : null}
            </div>

            {err && (
              <div className="bg-red-50 border border-red-200 rounded-lg px-3 py-2.5 text-sm text-red-600">
                {err}
              </div>
            )}

            <button
              className="w-full rounded-lg bg-zinc-900 py-3 text-sm font-semibold text-white shadow-md shadow-zinc-900/20 transition hover:bg-zinc-800 disabled:opacity-60"
              disabled={loading}
            >
              {loading ? "Please wait…" : mode === "login" ? "Sign in" : "Create account"}
            </button>
          </form>

          <div className="mt-4 space-y-3">
            <div className="relative">
              <div className="absolute inset-0 flex items-center"><div className="w-full border-t border-zinc-100" /></div>
              <div className="relative flex justify-center"><span className="bg-white px-2 text-xs text-zinc-400">or</span></div>
            </div>

            <a
              href={`${BASE}/v1/auth/google`}
              className="w-full flex items-center justify-center gap-2.5 border border-zinc-200 rounded-lg py-2.5 text-sm font-medium text-zinc-700 hover:bg-zinc-50 transition-colors"
            >
              <svg className="w-4 h-4" viewBox="0 0 24 24">
                <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z"/>
                <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
              </svg>
              Continue with Google
            </a>

            <a
              href={`${BASE}/v1/auth/github`}
              className="w-full flex items-center justify-center gap-2.5 border border-zinc-200 rounded-lg py-2.5 text-sm font-medium text-zinc-700 hover:bg-zinc-50 transition-colors"
            >
              <svg className="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/>
              </svg>
              Continue with GitHub
            </a>

            <a
              href={`${BASE}/v1/auth/gitlab`}
              className="w-full flex items-center justify-center gap-2.5 border border-zinc-200 rounded-lg py-2.5 text-sm font-medium text-zinc-700 hover:bg-zinc-50 transition-colors"
            >
              <svg className="w-4 h-4 text-[#e24329]" viewBox="0 0 24 24" aria-hidden="true" fill="currentColor">
                <path d="M22.65 14.39L12 22.13 1.35 14.39a.84.84 0 0 1-.3-.94l1.22-3.78 2.44-7.51A.42.42 0 0 1 4.82 2a.43.43 0 0 1 .58 0 .42.42 0 0 1 .11.18l2.44 7.49h8.1l2.44-7.51a.42.42 0 0 1 .11-.18.43.43 0 0 1 .58 0 .42.42 0 0 1 .11.18l2.44 7.51L23 13.45a.84.84 0 0 1-.35.94z"/>
              </svg>
              Continue with GitLab
            </a>

            <div className="text-center">
              <button
                type="button"
                className="text-sm text-zinc-500 hover:text-zinc-700 transition-colors"
                onClick={() => { setMode(mode === "login" ? "signup" : "login"); setErr(null); setPasswordError(null); }}
              >
                {mode === "login" ? "Don't have an account? Sign up" : "Already have an account? Sign in"}
              </button>
            </div>
          </div>
          </div>
          </div>

          {/* Sample preview — secondary, desktop only inline */}
          <div className="hidden lg:block lg:pt-0">
            <SampleEvidencePanel
              loading={sampleLoading}
              error={sampleError}
              onDownload={downloadSamplePack}
            />
          </div>
        </div>

        {/* Mobile / tablet: compact sample below login */}
        <div className="mt-6 lg:hidden max-w-md mx-auto">
          <SampleEvidencePanel
            compact
            loading={sampleLoading}
            error={sampleError}
            onDownload={downloadSamplePack}
          />
        </div>
      </div>
    </div>
  );
}
