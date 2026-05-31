import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "../api";

type IaCResponse = {
  iac_status: string;
  reason?: string;
  terraform?: string | null;
  cloudformation?: string | null;
  cli?: string[];
  hints?: string[];
  pr_automation?: {
    available: boolean;
    github_connected?: boolean;
    gitlab_connected?: boolean;
    providers?: string[];
    repos: { full_name: string; default_branch: string }[];
    note: string;
  };
  apply_paths?: {
    terraform_pr: boolean;
    terraform_generic: boolean;
    customer_automation: boolean;
  };
};

type DispatchResponse = {
  plan: Record<string, unknown>;
  plan_id?: string;
  automation_region?: string;
  document_name?: string;
  resource_region?: string;
  region?: string;
  iam_inline_policy?: Record<string, unknown>;
  signing_public_key_base64?: string | null;
  automation_execution_id?: string | null;
  automation_error?: string | null;
  cli: { put_events?: string; start_automation?: string };
  cfn_template_url: string;
  instructions: string[];
};

function CopyBlock({ label, text }: { label: string; text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="mt-2">
      <div className="mb-1 flex items-center justify-between gap-2">
        <span className="text-[11px] font-medium text-zinc-600">{label}</span>
        <button
          type="button"
          className="text-[11px] font-medium text-indigo-600 hover:text-indigo-800"
          onClick={() => {
            void navigator.clipboard.writeText(text);
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          }}
        >
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className="max-h-64 overflow-auto rounded-lg border border-zinc-200 bg-zinc-950 p-3 text-[11px] leading-relaxed text-zinc-100">
        {text}
      </pre>
    </div>
  );
}

function versionControlPrLabel(providers: string[]): string {
  if (providers.length > 1) return "Version control PR";
  if (providers[0] === "gitlab") return "GitLab merge request";
  return "Git PR";
}

/** Terraform or customer automation panels embedded under Remediation steps (Console | CLI | …). */
type RunnerStatus = {
  ready: boolean;
  automation_region: string;
  blockers: string[];
  warnings: string[];
  hints: string[];
  rule: { exists: boolean; state?: string | null };
  lambda: { exists: boolean };
  schema_discovery?: { enabled: boolean | null; note?: string };
};

export function IaCRemediationSection({
  findingId,
  checkId,
  embedMode,
  accountId,
}: {
  findingId: string;
  checkId: string;
  bucketName?: string;
  embedMode: "terraform" | "automation";
  accountId?: string | null;
}) {
  const [dispatch, setDispatch] = useState<DispatchResponse | null>(null);

  const { data: runnerStatus } = useQuery({
    queryKey: ["remediation-runner-status", accountId],
    queryFn: () => api<RunnerStatus>(`/v1/accounts/${accountId}/remediation-runner/status`),
    enabled: embedMode === "automation" && !!accountId,
    staleTime: 60_000,
  });

  const { data, isLoading, error } = useQuery({
    queryKey: ["iac-snippets", findingId],
    queryFn: () => api<IaCResponse>(`/v1/findings/${findingId}/iac-snippets`),
  });

  const dispatchMutation = useMutation({
    mutationFn: () =>
      api<DispatchResponse>(`/v1/findings/${findingId}/remediation/dispatch`, {
        method: "POST",
        body: JSON.stringify({}),
      }),
    onSuccess: (res) => setDispatch(res),
  });

  if (isLoading) {
    return <p className="text-[13px] text-zinc-500">Loading remediation templates…</p>;
  }
  if (error || !data) {
    return <p className="text-[13px] text-zinc-600">Could not load IaC snippets.</p>;
  }

  if (embedMode === "terraform") {
    if (
      data.iac_status === "automation_only" ||
      !data.apply_paths?.terraform_generic ||
      !data.terraform
    ) {
      return (
        <p className="text-[13px] leading-relaxed text-zinc-600">
          {data.reason ?? "No IaC template for this check yet — use Console/CLI instead."}
        </p>
      );
    }

    const providers = data.pr_automation?.providers ?? [];
    const showPrPaused =
      (data.pr_automation?.github_connected || data.pr_automation?.gitlab_connected) &&
      !data.apply_paths?.terraform_pr;
    const showPrReady = data.apply_paths?.terraform_pr && data.pr_automation?.github_connected;

    return (
      <div className="space-y-4">
        {showPrPaused && (
          <p className="rounded-lg border border-zinc-200 bg-zinc-50 px-3 py-2 text-[11px] leading-relaxed text-zinc-600">
            <span className="font-semibold text-zinc-800">
              {versionControlPrLabel(providers)}
            </span>{" "}
            automation is paused for this check — copy Terraform below or use Remediation → Automation.
          </p>
        )}
        {showPrReady && data.pr_automation?.repos?.[0] && (
          <p className="rounded-lg border border-indigo-200 bg-indigo-50/60 px-3 py-2 text-[11px] text-indigo-950">
            Repo-aware PRs use <span className="font-semibold">hclpatch</span> +{" "}
            <span className="font-semibold">terraform validate</span> — call{" "}
            <code className="text-[10px]">POST /v1/findings/…/iac/terraform-pr</code> with a connected repo.
          </p>
        )}

        <div>
          <p className="text-[12px] font-semibold text-zinc-800">Terraform</p>
          <p className="mt-0.5 text-[11px] text-zinc-500">
            Runnable module for this finding — <code className="text-[10px]">terraform init</code> then{" "}
            <code className="text-[10px]">terraform apply</code> (AWS CLI + credentials required).
          </p>
          <CopyBlock label="remediation.tf" text={data.terraform} />
        </div>

        {data.hints?.map((h) => (
          <p key={h} className="text-[11px] text-zinc-500">
            {h}
          </p>
        ))}
      </div>
    );
  }

  if (!data.apply_paths?.customer_automation) {
    return (
      <p className="text-[13px] leading-relaxed text-zinc-600">
        Customer automation is not available for this check yet. Use Console or CLI above.
      </p>
    );
  }

  return (
    <div className="space-y-3">
      {accountId && runnerStatus && (
        <div
          className={`rounded-lg border px-3 py-2.5 text-[12px] leading-relaxed ${
            runnerStatus.ready
              ? "border-emerald-200 bg-emerald-50/80 text-emerald-950"
              : "border-amber-200 bg-amber-50/90 text-amber-950"
          }`}
        >
          <p className="font-semibold">
            {runnerStatus.ready
              ? `Automation ready in ${runnerStatus.automation_region}`
              : "SSM automation not verified — deploy before execution"}
          </p>
          {runnerStatus.blockers.map((b) => (
            <p key={b} className="mt-1">
              {b}
            </p>
          ))}
          {runnerStatus.warnings.map((w) => (
            <p key={w} className="mt-1 text-[11px] opacity-90">
              {w}
            </p>
          ))}
          {!runnerStatus.ready &&
            runnerStatus.hints.map((h) => (
              <p key={h} className="mt-1 font-mono text-[10px]">
                {h}
              </p>
            ))}
        </div>
      )}

      <ol className="list-decimal space-y-1.5 pl-4 text-[12px] leading-relaxed text-zinc-700">
        <li>
          Deploy{" "}
          <a
            href="https://github.com/awakzdev/Vigil/blob/main/infra/cfn/vigil-remediation-ssm.yaml"
            target="_blank"
            rel="noreferrer"
            className="font-medium text-amber-900 underline"
          >
            vigil-remediation-ssm.yaml
          </a>{" "}
          in <span className="font-mono">{runnerStatus?.automation_region ?? "REMEDIATION_AUTOMATION_REGION"}</span> (automation
          home region, not necessarily the resource region).
        </li>
        <li>Confirm document <span className="font-mono">Vigil-RemediationPlanExecutor</span> exists.</li>
        <li>Prepare below, then run <code className="text-[10px]">start-automation-execution</code>.</li>
      </ol>

      <button
        type="button"
        disabled={dispatchMutation.isPending || (runnerStatus != null && !runnerStatus.ready)}
        onClick={() => dispatchMutation.mutate()}
        className="rounded-lg bg-amber-900 px-3 py-1.5 text-[12px] font-semibold text-amber-50 disabled:cursor-not-allowed disabled:opacity-50"
      >
        {dispatchMutation.isPending ? "Preparing…" : "Prepare SSM Automation"}
      </button>

      {dispatch && (
        <div className="space-y-2 rounded-lg border border-amber-100 bg-amber-50/40 px-3 py-3">
          {dispatch.automation_region && (
            <p className="text-[11px] text-amber-950">
              SSM automation region:{" "}
              <span className="font-mono font-semibold">{dispatch.automation_region}</span>
              {dispatch.document_name && (
                <>
                  {" "}
                  · document: <span className="font-mono font-semibold">{dispatch.document_name}</span>
                </>
              )}
              {dispatch.resource_region && dispatch.resource_region !== dispatch.automation_region && (
                <>
                  {" "}
                  · API region: <span className="font-mono font-semibold">{dispatch.resource_region}</span>
                </>
              )}
            </p>
          )}
          {dispatch.iam_inline_policy && (
            <CopyBlock
              label="Inline policy for this check (attach to VigilRemediationRole)"
              text={JSON.stringify(dispatch.iam_inline_policy, null, 2)}
            />
          )}
          {dispatch.automation_execution_id && (
            <p className="rounded-md border border-emerald-200 bg-emerald-50 px-2 py-1.5 text-[11px] font-medium text-emerald-900">
              Started SSM Automation execution{" "}
              <span className="font-mono">{dispatch.automation_execution_id}</span>.
            </p>
          )}
          {dispatch.automation_error && (
            <p className="rounded-md border border-amber-200 bg-amber-50 px-2 py-1.5 text-[11px] text-amber-950">
              Vigil could not start SSM automatically: {dispatch.automation_error}. Use the CLI fallback below.
            </p>
          )}
          <CopyBlock
            label="aws ssm start-automation-execution (run in target account)"
            text={dispatch.cli.start_automation ?? dispatch.cli.put_events ?? ""}
          />
          {dispatch.instructions.map((line) => (
            <p key={line} className="text-[10px] text-amber-900/85">
              {line}
            </p>
          ))}
        </div>
      )}

      <ExecutionStatus findingId={findingId} />
    </div>
  );
}

function ExecutionStatus({ findingId }: { findingId: string }) {
  const { data } = useQuery({
    queryKey: ["remediation-execution", findingId],
    queryFn: () =>
      api<{
        status: string;
        plan_id?: string;
        completed_at?: string;
        error?: string;
        result?: { ok?: boolean };
      }>(`/v1/findings/${findingId}/remediation-execution`),
    refetchInterval: 15_000,
  });
  if (!data || data.status === "none") return null;
  const ok = data.status === "success" || data.result?.ok;
  return (
    <p
      className={`rounded-lg border px-3 py-2 text-[12px] ${
        ok ? "border-emerald-200 bg-emerald-50 text-emerald-900" : "border-zinc-200 bg-zinc-50 text-zinc-700"
      }`}
    >
      Execution <span className="font-semibold">{data.status}</span>
      {data.plan_id && <> · plan <span className="font-mono text-[11px]">{data.plan_id.slice(0, 8)}…</span></>}
      {data.error && <> — {data.error}</>}
    </p>
  );
}
