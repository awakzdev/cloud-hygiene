import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
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
  ssm_remediation?: SsmRemediationMeta;
};

type SsmRemediationMeta = {
  module_id: string;
  module_label: string;
  module_enabled: boolean;
  module_deployed: boolean;
  action: string | null;
  action_label: string;
  execution: string;
  automation_role_name: string;
  resource_region: string;
  automation_region: string;
  runbook?: { document_name: string; owner: string; note?: string } | null;
  requires_vigil_document: boolean;
};

type DispatchResponse = {
  plan: Record<string, unknown>;
  plan_id?: string;
  automation_region?: string;
  document_name?: string;
  resource_region?: string;
  iam_inline_policy?: Record<string, unknown>;
  automation_execution_id?: string | null;
  automation_error?: string | null;
  prepared?: boolean;
  executed?: boolean;
  cli: { put_events?: string; start_automation?: string };
  cfn_template_url: string;
  instructions: string[];
};

type RunnerStatus = {
  ready: boolean;
  automation_region: string;
  blockers: string[];
  warnings: string[];
  hints: string[];
  document?: { name: string; exists: boolean; status?: string | null };
};

function formatAutomationStartError(message: string): string {
  if (
    message.includes("AccessDenied") &&
    message.includes("ssm:StartAutomationExecution") &&
    message.includes("VigilScannerRole")
  ) {
    if (message.includes(":document/")) {
      return (
        "VigilScannerRole has VigilSsmRemediationStart but it does not allow StartAutomationExecution on this " +
        "document ARN. Update VigilAccountConnector to the latest connector template (document resource in IAM), " +
        "wait for UPDATE_COMPLETE, then Accounts → Verify capabilities and Retry."
      );
    }
    return (
      "VigilScannerRole is missing ssm:StartAutomationExecution. " +
      "Update your VigilAccountConnector CloudFormation stack with SSM remediation modules enabled " +
      "(EnableIamAccessKeyRemediation=Yes, etc.), then Accounts → Verify capabilities."
    );
  }
  if (message.includes("AutomationAssumeRole") && message.includes("Unknown parameter")) {
    return (
      "The API sent an invalid StartAutomationExecution parameter (AutomationAssumeRole). " +
      "Restart the Vigil API to pick up the latest build, then Retry."
    );
  }
  return message;
}

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

function SsmDetail({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0 rounded-lg border border-zinc-200/70 bg-zinc-50/70 px-3 py-2">
      <dt className="text-[10px] font-semibold uppercase tracking-wider text-zinc-400">{label}</dt>
      <dd className="mt-1 truncate text-[12px] font-medium text-zinc-800">{children}</dd>
    </div>
  );
}

function SsmStatusBadge({
  tone,
  children,
}: {
  tone: "ready" | "loading" | "blocked" | "failed" | "running" | "completed";
  children: React.ReactNode;
}) {
  const toneClass = {
    ready: "bg-emerald-50 text-emerald-800 ring-emerald-200/80",
    loading: "bg-zinc-100 text-zinc-600 ring-zinc-200/80",
    blocked: "bg-amber-50 text-amber-900 ring-amber-200/80",
    failed: "bg-amber-50 text-amber-900 ring-amber-200/80",
    running: "bg-indigo-50 text-indigo-800 ring-indigo-200/80",
    completed: "bg-emerald-50 text-emerald-800 ring-emerald-200/80",
  }[tone];

  return (
    <span className={`inline-flex shrink-0 items-center rounded-full px-2.5 py-1 text-[11px] font-semibold ring-1 ${toneClass}`}>
      {children}
    </span>
  );
}

function SsmRemediationPanel({
  findingId,
  checkId,
  accountId,
  resourceRegion,
  ssm,
}: {
  findingId: string;
  checkId: string;
  accountId: string | null;
  resourceRegion: string;
  ssm: SsmRemediationMeta;
}) {
  const [dispatch, setDispatch] = useState<DispatchResponse | null>(null);
  /** True after user clicks Start remediation this drawer session (avoids stale DB failures on Ready). */
  const [attemptedStart, setAttemptedStart] = useState(false);
  const qc = useQueryClient();

  const { data: runnerStatus, isLoading: runnerLoading } = useQuery({
    queryKey: ["remediation-runner-status", accountId, checkId, resourceRegion],
    queryFn: () =>
      api<RunnerStatus>(
        `/v1/accounts/${accountId}/remediation-runner/status?check_id=${encodeURIComponent(checkId)}&resource_region=${encodeURIComponent(resourceRegion)}`,
      ),
    enabled: !!accountId && ssm.module_enabled,
    staleTime: 60_000,
  });

  const { data: persistedExecution } = useRemediationExecution(findingId);

  const startMutation = useMutation({
    mutationFn: () =>
      api<DispatchResponse>(`/v1/findings/${findingId}/remediation/dispatch`, {
        method: "POST",
        body: JSON.stringify({ execute: true }),
      }),
    onSuccess: (res) => {
      setDispatch(res);
      setAttemptedStart(true);
      void qc.invalidateQueries({ queryKey: ["remediation-execution", findingId] });
    },
  });

  useEffect(() => {
    setDispatch(null);
    setAttemptedStart(false);
  }, [findingId]);

  useEffect(() => {
    if (!persistedExecution || persistedExecution.status === "none") return;
    const active =
      persistedExecution.status === "running" ||
      persistedExecution.status === "dispatched" ||
      Boolean(persistedExecution.automation_execution_id);
    if (active) {
      setAttemptedStart(true);
      if (persistedExecution.automation_execution_id) {
        setDispatch((prev) => {
          if (prev?.automation_execution_id === persistedExecution.automation_execution_id) return prev;
          return {
            ...(prev ?? {}),
            plan_id: persistedExecution.plan_id,
            automation_execution_id: persistedExecution.automation_execution_id,
            automation_error: persistedExecution.error ?? null,
            executed: true,
          } as DispatchResponse;
        });
      }
    } else if (persistedExecution.status === "failed" && persistedExecution.error) {
      setAttemptedStart(true);
      setDispatch((prev) => {
        if (prev?.automation_error === persistedExecution.error && !prev.automation_execution_id) return prev;
        return {
          ...(prev ?? {}),
          plan_id: persistedExecution.plan_id,
          automation_execution_id: null,
          automation_error: persistedExecution.error ?? "automation_start_failed",
          executed: false,
        } as DispatchResponse;
      });
    }
  }, [findingId, persistedExecution]);

  if (!ssm.module_enabled) {
    return (
      <div className="rounded-xl border border-amber-200/80 bg-amber-50/70 p-4">
        <div className="flex items-start justify-between gap-3">
          <div>
            <p className="text-[13px] font-semibold text-zinc-900">Automated fix</p>
            <p className="mt-1 text-[12px] leading-relaxed text-amber-950">
              Enable <span className="font-semibold">{ssm.module_label}</span> in the AWS connector before running this fix.
            </p>
          </div>
          <SsmStatusBadge tone="blocked">Not enabled</SsmStatusBadge>
        </div>
        <Link
          to="/accounts"
          className="mt-3 inline-flex rounded-lg bg-zinc-900 px-3 py-1.5 text-[12px] font-semibold text-white hover:bg-zinc-800"
        >
          Update AWS connector
        </Link>
      </div>
    );
  }

  const ready = runnerStatus?.ready === true;
  const running = startMutation.isPending;
  const execStatus = persistedExecution?.status;
  const execSuccess =
    execStatus === "success" || Boolean((persistedExecution?.result as { ok?: boolean } | undefined)?.ok);
  const execInProgress = execStatus === "running" || execStatus === "dispatched";
  const execFailedPersisted = execStatus === "failed" && Boolean(persistedExecution?.error);
  const started =
    Boolean(dispatch?.automation_execution_id) || execInProgress || execSuccess;
  const startFailed = Boolean(dispatch?.automation_error) || (execFailedPersisted && !execInProgress && !execSuccess);
  const usesCustomDoc = ssm.requires_vigil_document;
  const documentName = ssm.runbook?.document_name ?? "Vigil-RemediationPlanExecutor";
  const documentOwner = ssm.runbook?.owner === "aws" ? "AWS-owned" : "Vigil";
  const runbookLabel =
    documentOwner === "AWS-owned" ? documentName : "Vigil guarded runbook";
  const executionRegion = ssm.automation_region;
  const targetRegion = ssm.resource_region;
  const regionsDiffer =
    Boolean(targetRegion && executionRegion && targetRegion !== executionRegion);

  return (
    <div className="space-y-3">
      <section className="overflow-hidden rounded-xl border border-zinc-200/80 bg-white shadow-sm shadow-zinc-900/[0.03]">
        <div className="flex items-start justify-between gap-3 border-b border-zinc-100 bg-zinc-50/80 px-4 py-3">
          <div className="min-w-0">
            <p className="text-[13px] font-semibold text-zinc-900">Automated fix</p>
            <p className="mt-0.5 truncate text-[11px] text-zinc-500">
              {ssm.execution || "AWS Systems Manager Automation"}
            </p>
          </div>
          {runnerLoading ? (
            <SsmStatusBadge tone="loading">Checking</SsmStatusBadge>
          ) : execSuccess ? (
            <SsmStatusBadge tone="completed">Completed</SsmStatusBadge>
          ) : startFailed ? (
            <SsmStatusBadge tone="failed">Failed</SsmStatusBadge>
          ) : execInProgress || started ? (
            <SsmStatusBadge tone="running">Running</SsmStatusBadge>
          ) : ready ? (
            <SsmStatusBadge tone="ready">Ready</SsmStatusBadge>
          ) : (
            <SsmStatusBadge tone="blocked">Not ready</SsmStatusBadge>
          )}
        </div>

        <div className="space-y-3 px-4 py-3.5">
          {runnerLoading && (
            <p className="text-[12px] text-zinc-500">Checking SSM remediation in your account…</p>
          )}

          {!runnerLoading && !ready && runnerStatus && (
            <div className="rounded-xl border border-amber-200/70 bg-amber-50/80 px-3 py-2.5 text-[12px] leading-relaxed text-amber-950">
              <p className="font-semibold">
                {usesCustomDoc
                  ? `SSM automation is not ready (home region ${executionRegion})`
                  : `SSM automation is not ready in ${targetRegion || executionRegion}`}
                .
              </p>
              <ul className="mt-2 list-disc space-y-1.5 pl-4 text-zinc-700 marker:text-amber-600">
                {runnerStatus.blockers.map((b) => (
                  <li key={b} className="break-words">
                    {b}
                  </li>
                ))}
              </ul>
              <Link
                to="/accounts"
                className="mt-3 inline-flex rounded-lg border border-indigo-200 bg-white px-3.5 py-2 text-[12px] font-semibold text-indigo-800 shadow-sm hover:bg-indigo-50"
              >
                Update AWS connector
              </Link>
            </div>
          )}

          {execSuccess && (
            <div className="rounded-xl border border-emerald-200/70 bg-emerald-50/70 px-3 py-2.5 text-[12px] text-emerald-950">
              <p className="font-semibold">Remediation finished</p>
              <p className="mt-1 leading-relaxed text-emerald-900/85">
                SSM Automation completed successfully. Click Verify below — for this check, Vigil confirms the fix in
                AWS directly (usually a few seconds).
              </p>
              {persistedExecution?.plan_id && (
                <p className="mt-1 font-mono text-[11px] text-emerald-900/70">
                  Plan {persistedExecution.plan_id.slice(0, 8)}…
                </p>
              )}
            </div>
          )}

          {!runnerLoading && ready && !started && !startFailed && !execSuccess && (
            <>
              <div className="rounded-xl border border-emerald-200/70 bg-emerald-50/60 px-3 py-2.5">
                <p className="text-[11px] font-semibold uppercase tracking-wider text-emerald-700">What will run</p>
                <p className="mt-1 text-[12px] leading-relaxed text-zinc-700">
                  Signed remediation plan via {ssm.execution || "AWS Systems Manager Automation"}. You start execution
                  explicitly; Vigil will not auto-run fixes.
                  {regionsDiffer && (
                    <>
                      {" "}
                      Automation starts in{" "}
                      <span className="font-mono font-medium">{executionRegion}</span>; the plan targets resources in{" "}
                      <span className="font-mono font-medium">{targetRegion}</span>.
                    </>
                  )}
                </p>
              </div>

              <dl className="grid grid-cols-2 gap-2">
                <SsmDetail label="Action">{ssm.action_label}</SsmDetail>
                <SsmDetail label="Execution region">
                  <span className="font-mono">{executionRegion}</span>
                </SsmDetail>
                <SsmDetail label="Target resource region">
                  <span className="font-mono">{targetRegion}</span>
                </SsmDetail>
                <SsmDetail label="Runbook">
                  <span title={documentOwner === "AWS-owned" ? documentName : documentName}>
                    {runbookLabel}
                  </span>
                </SsmDetail>
                <SsmDetail label="Role">
                  <span className="font-mono" title={ssm.automation_role_name}>
                    {ssm.automation_role_name}
                  </span>
                </SsmDetail>
              </dl>

              <div className="flex flex-col gap-2 pt-1 sm:flex-row sm:items-center sm:justify-between">
                <button
                  type="button"
                  disabled={running || !accountId}
                  onClick={() => {
                    setAttemptedStart(true);
                    startMutation.mutate();
                  }}
                  className="inline-flex items-center justify-center gap-2 rounded-lg bg-zinc-900 px-4 py-2 text-[12px] font-semibold text-white shadow-sm shadow-zinc-900/10 transition hover:bg-zinc-800 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {running && (
                    <span
                      className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-white/30 border-t-white"
                      aria-hidden
                    />
                  )}
                  {running ? "Starting…" : "Start remediation"}
                </button>
                <p className="text-[11px] leading-relaxed text-zinc-500 sm:max-w-[16rem] sm:text-right">
                  Review Console or CLI first when the change needs human context.
                </p>
              </div>
            </>
          )}

          {started && !execSuccess && (
            <div className="space-y-2 text-[12px]">
              <div className="rounded-xl border border-emerald-200/70 bg-emerald-50/70 px-3 py-2.5">
                <p className="font-semibold text-emerald-950">Execution dispatched</p>
                <p className="mt-1 break-all font-mono text-[11px] text-zinc-700">
                  {dispatch!.automation_execution_id}
                </p>
                <p className="mt-1 text-zinc-600">
                  In progress in {executionRegion}. Refresh below or re-scan to verify the finding.
                </p>
              </div>
              <button
                type="button"
                disabled={running}
                onClick={() => {
                  setAttemptedStart(true);
                  startMutation.mutate();
                }}
                className="text-[11px] font-medium text-indigo-700 underline disabled:opacity-50"
              >
                Start again
              </button>
            </div>
          )}

          {startFailed && (
            <div className="rounded-xl border border-amber-200/80 bg-amber-50/80 px-3 py-2.5 text-[12px] text-amber-950">
              <p className="font-semibold">Could not start SSM Automation</p>
              <p className="mt-1.5 leading-relaxed">
                {formatAutomationStartError(dispatch!.automation_error ?? "")}
              </p>
              {dispatch!.plan_id && (
                <p className="mt-2 font-mono text-[11px] text-amber-900/75">
                  Plan {dispatch.plan_id.slice(0, 8)}… (saved; not executed)
                </p>
              )}
              <div className="mt-3 flex flex-wrap items-center gap-2">
                {dispatch!.automation_error?.includes("StartAutomationExecution") && (
                  <Link
                    to="/accounts"
                    className="inline-flex rounded-lg border border-indigo-200 bg-white px-3.5 py-2 text-[12px] font-semibold text-indigo-800 shadow-sm hover:bg-indigo-50"
                  >
                    Update AWS connector
                  </Link>
                )}
                <button
                  type="button"
                  disabled={running}
                  onClick={() => {
                    setAttemptedStart(true);
                    startMutation.mutate();
                  }}
                  className="inline-flex items-center gap-2 rounded-lg border border-amber-300/70 bg-white px-3.5 py-1.5 text-[12px] font-semibold text-amber-950 transition hover:bg-amber-50 disabled:opacity-50"
                >
                  {running && (
                    <span
                      className="h-3 w-3 animate-spin rounded-full border-2 border-amber-300 border-t-amber-800"
                      aria-hidden
                    />
                  )}
                  {running ? "Retrying…" : "Retry"}
                </button>
              </div>
            </div>
          )}
        </div>
      </section>

      {!attemptedStart && !startFailed && !execSuccess && (
        <PreviousExecutionNote findingId={findingId} />
      )}

      {!startFailed && (
        <ExecutionStatus findingId={findingId} showStaleFailures={attemptedStart} />
      )}
    </div>
  );
}

export function IaCRemediationSection({
  findingId,
  checkId,
  embedMode,
  accountId,
  resourceRegion,
}: {
  findingId: string;
  checkId: string;
  bucketName?: string;
  embedMode: "terraform" | "automation";
  accountId?: string | null;
  resourceRegion?: string | null;
}) {
  const { data, isLoading, error } = useQuery({
    queryKey: ["iac-snippets", findingId],
    queryFn: () => api<IaCResponse>(`/v1/findings/${findingId}/iac-snippets`),
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
          {data.reason ?? "No IaC template for this check yet — use Console or CLI instead."}
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
        SSM remediation is not available for this check yet. Use Console or CLI above.
      </p>
    );
  }

  if (!data.ssm_remediation) {
    return (
      <p className="text-[13px] leading-relaxed text-zinc-600">
        Could not load SSM remediation metadata for this finding.
      </p>
    );
  }

  const region =
    resourceRegion ??
    data.ssm_remediation.resource_region ??
    data.ssm_remediation.automation_region ??
    "us-east-1";

  return (
    <SsmRemediationPanel
      findingId={findingId}
      checkId={checkId}
      accountId={accountId ?? null}
      resourceRegion={region}
      ssm={data.ssm_remediation}
    />
  );
}

type RemediationExecutionRow = {
  status: string;
  plan_id?: string;
  completed_at?: string;
  error?: string;
  result?: { ok?: boolean };
  automation_execution_id?: string | null;
};

function useRemediationExecution(findingId: string) {
  return useQuery({
    queryKey: ["remediation-execution", findingId],
    queryFn: () => api<RemediationExecutionRow>(`/v1/findings/${findingId}/remediation-execution`),
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === "running" || status === "dispatched" ? 5_000 : false;
    },
  });
}

/** Prior failed run when the panel is Ready again (not this session). */
function PreviousExecutionNote({ findingId }: { findingId: string }) {
  const { data } = useRemediationExecution(findingId);
  if (!data || data.status !== "failed" || !data.error) return null;
  return (
    <div className="rounded-lg border border-zinc-200 bg-zinc-50 px-3 py-2 text-[11px] leading-relaxed text-zinc-600">
      <p className="font-semibold text-zinc-700">Previous attempt (not this session)</p>
      <p className="mt-1 text-zinc-600">{formatAutomationStartError(data.error)}</p>
      {data.plan_id && (
        <p className="mt-1 font-mono text-[10px] text-zinc-500">Plan {data.plan_id.slice(0, 8)}…</p>
      )}
    </div>
  );
}

function ExecutionStatus({
  findingId,
  showStaleFailures,
}: {
  findingId: string;
  /** When false, hide terminal failed records from before this drawer session. */
  showStaleFailures: boolean;
}) {
  const { data, refetch } = useRemediationExecution(findingId);
  if (!data || data.status === "none") return null;
  const ok = data.status === "success" || data.result?.ok;
  const failed = data.status === "failed";
  const inProgress = data.status === "running";
  const dispatchedOnly = data.status === "dispatched";
  const terminal = failed || ok;
  if (terminal && !showStaleFailures) return null;
  if (dispatchedOnly && !data.error && !showStaleFailures) return null;
  return (
    <div
      className={`rounded-lg border px-3 py-2 text-[12px] ${
        ok
          ? "border-emerald-200 bg-emerald-50 text-emerald-900"
          : failed
            ? "border-amber-200 bg-amber-50/80 text-amber-950"
            : "border-zinc-200 bg-zinc-50 text-zinc-700"
      }`}
    >
      <div className="flex items-start justify-between gap-2">
        <p className="min-w-0 leading-relaxed">
          {ok ? (
            <>
              Execution <span className="font-semibold">completed</span>
            </>
          ) : failed ? (
            <>
              Execution <span className="font-semibold">did not start</span>
            </>
          ) : inProgress ? (
            <>
              Execution <span className="font-semibold">in progress</span>
            </>
          ) : (
            <>
              Execution <span className="font-semibold">{data.status}</span>
            </>
          )}
          {data.plan_id && (
            <>
              {" "}
              · plan <span className="font-mono text-[11px]">{data.plan_id.slice(0, 8)}…</span>
            </>
          )}
          {data.error && (
            <span className="mt-1 block text-[11px] leading-snug opacity-90">
              {formatAutomationStartError(data.error)}
            </span>
          )}
        </p>
        {inProgress && (
          <button
            type="button"
            onClick={() => void refetch()}
            className="shrink-0 text-[11px] font-medium text-indigo-700 underline"
          >
            Refresh status
          </button>
        )}
      </div>
    </div>
  );
}
