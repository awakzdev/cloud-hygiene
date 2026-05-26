import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, useEffect, useRef, useMemo, useCallback } from "react";
import { useSearchParams } from "react-router-dom";
import { api, token } from "../api";
import { FindingDrawer } from "../components/FindingDrawer";
import { SearchReferenceModal } from "../components/SearchReferenceModal";

type Finding = {
  id: string;
  check_id: string;
  resource_arn: string;
  title: string;
  severity: string;
  risk_score: number;
  status: string;
  evidence: Record<string, unknown>;
  first_seen: string;
  last_seen: string;
};

type FindingPage = {
  items: Finding[];
  total: number;
  next_cursor: string | null;
};

type Account = { id: string; status: string };

const COLLAPSED_FINDINGS_KEY = "vigil.findings.collapsedGroups";

const sevBadge: Record<string, string> = {
  critical: "border-red-200 bg-red-50 text-red-700",
  high: "border-red-200 bg-red-50 text-red-600",
  medium: "border-amber-200 bg-amber-50 text-amber-600",
  low: "border-zinc-200 bg-zinc-50 text-zinc-500",
};

const sevAccent: Record<string, string> = {
  critical: "border-l-2 border-l-red-300/70",
  high: "border-l-2 border-l-red-200/80",
  medium: "border-l-2 border-l-amber-300/60",
  low: "border-l-2 border-l-zinc-200/80",
};

const sevExpandedBg: Record<string, string> = {
  critical: "bg-red-50/[0.18]",
  high: "bg-red-50/[0.12]",
  medium: "bg-amber-50/[0.18]",
  low: "bg-zinc-50/40",
};

const sevWeight: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };


const checkLabels: Record<string, string> = {
  // IAM root
  "iam.root.has_access_keys": "Root has access keys",
  "iam.root.no_mfa": "Root MFA not enabled",
  "iam.root.usage": "Root account used recently",
  // IAM account
  "iam.account.password_policy_weak": "Weak password policy",
  // IAM users
  "iam.user.no_mfa": "MFA not enabled",
  "iam.user.inactive_90d": "Inactive user",
  // Access keys
  "iam.access_key.unused_90d": "Unused access key",
  "iam.access_key.no_rotation_90d": "Long-lived access key",
  "iam.access_key.multiple_active": "Multiple active access keys",
  // Roles
  "iam.role.unassumed_90d": "Role unassumed",
  "iam.role.wildcard_action": "Wildcard action",
  "iam.perm.granted_vs_used": "Write actions granted but never used",
  "iam.policy.wildcard_resource": "Wildcard resource in policy",
  "iam.policy.unattached": "Unattached managed policy",
  "iam.role.unused_services_90d": "Unused granted services",
  "iam.role.trust_wildcard": "Wildcard trust policy",
  // S3
  "s3.account.public_access_not_blocked": "Account public access not blocked",
  "s3.bucket.public_access_not_blocked": "Public access not blocked",
  "s3.bucket.no_https_policy": "No HTTPS-only policy",
  "s3.bucket.no_kms": "Not encrypted with KMS",
  "s3.bucket.no_logging": "Access logging disabled",
  // KMS
  "kms.key.no_rotation": "Key rotation disabled",
  // CloudTrail
  "cloudtrail.trail.not_enabled": "CloudTrail not enabled",
  "cloudtrail.trail.no_log_validation": "Log file validation disabled",
  "cloudtrail.trail.no_kms": "CloudTrail not encrypted with KMS",
  // GuardDuty
  "guardduty.detector.not_enabled": "GuardDuty not enabled",
  // Access Analyzer
  "aws.access_analyzer.not_enabled": "IAM Access Analyzer not enabled",
  // AWS Config
  "aws.config.not_enabled": "AWS Config not enabled",
  // Security Hub
  "aws.securityhub.not_enabled": "Security Hub not enabled",
  // VPC
  "vpc.flow_logs.not_enabled": "VPC flow logs disabled",
  // Security Groups
  "ec2.security_group.unrestricted_ssh": "Unrestricted SSH",
  "ec2.security_group.unrestricted_rdp": "Unrestricted RDP",
  "ec2.security_group.default_allows_traffic": "Default security group has rules",
  // EC2
  "ec2.instance.imdsv2_not_required": "IMDSv2 not required",
  "ec2.ebs.encryption_not_default": "EBS encryption not default",
  "ec2.ebs.volume_unencrypted": "EBS volume not encrypted",
  // RDS
  "rds.instance.publicly_accessible": "RDS publicly accessible",
  "rds.instance.no_encryption": "RDS storage not encrypted",
  "rds.instance.no_automated_backup": "RDS backups disabled",
  // GitHub
  "github.org.mfa_not_enforced": "GitHub MFA not enforced",
  "github.org.dormant_members": "GitHub dormant members",
  "github.repo.no_branch_protection": "No branch protection",
  "github.repo.self_merge_allowed": "Self-merge allowed",
  "github.repo.insufficient_reviews": "Insufficient PR reviews",
  // GitLab
  "gitlab.org.mfa_not_enforced": "GitLab MFA not enforced",
  "gitlab.org.dormant_members": "GitLab dormant members",
  "gitlab.repo.no_branch_protection": "No branch protection",
  "gitlab.repo.self_merge_allowed": "Self-merge allowed",
  "gitlab.repo.insufficient_reviews": "Insufficient MR reviews",
};

const checkDescriptions: Record<string, string> = {
  "iam.root.has_access_keys": "Root account access keys are permanent credentials — delete them.",
  "iam.root.no_mfa": "Root account without MFA can be compromised with credentials alone.",
  "iam.root.usage": "Root account should not be used for regular operations — use IAM users or roles instead.",
  "iam.account.password_policy_weak": "Strengthen the account password policy to enforce complexity and rotation.",
  "iam.user.no_mfa": "Require MFA for interactive IAM users.",
  "iam.user.inactive_90d": "Disable or remove dormant IAM users.",
  "iam.access_key.unused_90d": "Deactivate stale access keys, then delete after validation.",
  "iam.access_key.no_rotation_90d": "Rotate active keys older than 90 days.",
  "iam.access_key.multiple_active": "Valid during rotation, but persistent duplicates increase exposure.",
  "iam.role.unassumed_90d": "Confirm ownership, then remove roles that are no longer used.",
  "iam.role.wildcard_action": "Replace wildcard permissions with scoped actions.",
  "iam.perm.granted_vs_used": "Scope role policies down to the actions actually used — reduce the blast radius if this role is ever compromised.",
  "iam.policy.wildcard_resource": "Scope Resource: '*' to specific ARNs — or remove actions that don't need account-wide access.",
  "iam.policy.unattached": "Delete or archive customer-managed policies that are not attached to any principal.",
  "iam.role.unused_services_90d": "Trim unused service permissions from role policies.",
  "iam.role.trust_wildcard": "Trust policy allows an unrestricted principal.",
  "s3.account.public_access_not_blocked": "Enable account-level S3 Block Public Access to guard every bucket by default.",
  "s3.bucket.public_access_not_blocked": "Enable all four Block Public Access settings to prevent accidental exposure.",
  "s3.bucket.no_https_policy": "Add a bucket policy that denies requests where aws:SecureTransport is false.",
  "s3.bucket.no_kms": "Enable SSE-KMS to use customer-managed keys for encryption at rest.",
  "s3.bucket.no_logging": "Enable server access logging for audit and forensic visibility.",
  "kms.key.no_rotation": "Enable annual automatic rotation for customer-managed KMS keys.",
  "cloudtrail.trail.not_enabled": "Enable CloudTrail with multi-region logging to capture all API activity.",
  "cloudtrail.trail.no_log_validation": "Enable log file integrity validation to detect log tampering.",
  "cloudtrail.trail.no_kms": "Encrypt CloudTrail logs with a customer-managed KMS key.",
  "guardduty.detector.not_enabled": "Enable GuardDuty to detect threats, anomalies, and unauthorized activity.",
  "aws.access_analyzer.not_enabled": "Enable IAM Access Analyzer to surface over-permissive cross-account access.",
  "aws.config.not_enabled": "Enable AWS Config to maintain a continuous configuration change history.",
  "aws.securityhub.not_enabled": "Enable Security Hub to centralize security posture checks and findings.",
  "vpc.flow_logs.not_enabled": "Enable VPC flow logs for network-level visibility and forensics.",
  "ec2.security_group.unrestricted_ssh": "Remove 0.0.0.0/0 ingress on port 22 — use Systems Manager Session Manager instead.",
  "ec2.security_group.unrestricted_rdp": "Remove 0.0.0.0/0 ingress on port 3389 — use Fleet Manager for RDP access.",
  "ec2.security_group.default_allows_traffic": "Default security groups should have no rules — move traffic to named groups.",
  "ec2.instance.imdsv2_not_required": "Require IMDSv2 to prevent SSRF-based credential theft from instance metadata.",
  "ec2.ebs.encryption_not_default": "Enable default EBS encryption so all new volumes are encrypted at creation.",
  "ec2.ebs.volume_unencrypted": "Encrypt existing EBS volumes by copying snapshots with encryption enabled.",
  "rds.instance.publicly_accessible": "Set Publicly Accessible to No and place RDS in a private subnet.",
  "rds.instance.no_encryption": "Encrypt RDS storage — snapshot → copy with encryption → restore to new instance.",
  "rds.instance.no_automated_backup": "Enable automated backups with a retention period that matches your recovery objective.",
  // GitHub
  "github.org.mfa_not_enforced": "GitHub organization does not require MFA for all members.",
  "github.org.dormant_members": "Organization members with no activity in the last 90 days.",
  "github.repo.no_branch_protection": "Default branch has no protection rules — anyone can push directly.",
  "github.repo.self_merge_allowed": "Pull requests merged by their own author with no peer review.",
  "github.repo.insufficient_reviews": "Pull requests merged with fewer approvals than required.",
  // GitLab
  "gitlab.org.mfa_not_enforced": "GitLab group does not require two-factor authentication.",
  "gitlab.org.dormant_members": "Group members with no activity in the last 90 days.",
  "gitlab.repo.no_branch_protection": "Default branch has no protection rules — direct pushes are allowed.",
  "gitlab.repo.self_merge_allowed": "Merge requests merged by their own author without peer review.",
  "gitlab.repo.insufficient_reviews": "Merge requests merged with fewer approvals than required.",
};

const statusTabs = ["open", "ignored", "resolved", "all"] as const;
type StatusTab = (typeof statusTabs)[number];
type SeverityFilter = "all" | "critical_high" | "medium" | "low";
type SortKey = "severity" | "score" | "first_seen";

function loadCollapsedGroups(): Record<string, boolean> {
  try {
    const raw = localStorage.getItem(COLLAPSED_FINDINGS_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function resourceName(arn: string): string {
  // For region-scoped ARNs with no resource ID (e.g. guardduty detector, vpc flow logs),
  // surface the region instead of an empty/generic segment
  const parts = arn.split(":");
  const region = parts[3] ?? "";
  const tail = parts.pop() ?? arn;
  const [, rest = tail] = tail.split(/\/(.+)/);
  const [name, suffix] = rest.split("#");
  const label = name || rest;
  // If the label is just the service type with no meaningful ID, show the region
  const generic = ["detector", "trail", "vpc", "flow-log", "security-group"].includes(label);
  if (generic && region) return region;
  if (!suffix) return label;
  const masked = suffix.length > 12 ? `${suffix.slice(0, 4)}…${suffix.slice(-4)}` : suffix;
  return `${label} · ${masked}`;
}

function daysAgo(iso: string): string {
  const d = Math.floor((Date.now() - new Date(iso).getTime()) / 86400000);
  if (d <= 0) return "today";
  if (d === 1) return "1d";
  if (d < 30) return `${d}d`;
  if (d < 365) return `${Math.floor(d / 30)}mo`;
  return `${Math.floor(d / 365)}y`;
}

function lastScanLabel(iso: string): string {
  const date = new Date(iso);
  const sameDay = date.toDateString() === new Date().toDateString();
  const time = date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  return sameDay ? `today at ${time}` : `${date.toLocaleDateString()} at ${time}`;
}

function matchesSeverityFilter(f: Finding, filter: SeverityFilter): boolean {
  if (filter === "all") return true;
  if (filter === "critical_high") return f.severity === "critical" || f.severity === "high";
  return f.severity === filter;
}

function sortLabel(k: SortKey): string {
  if (k === "first_seen") return "Age";
  return k.charAt(0).toUpperCase() + k.slice(1);
}

function sortIcon(k: SortKey, active: SortKey, dir: "asc" | "desc"): string {
  if (k !== active) return "";
  return dir === "asc" ? "↑" : "↓";
}

const ALL_CHECK_IDS = Object.keys(checkLabels);

function TagSearchInput({
  tags,
  onTagsChange,
}: {
  tags: string[];
  onTagsChange: (t: string[]) => void;
}) {
  const [input, setInput] = useState("");
  const [open, setOpen] = useState(false);
  const [hi, setHi] = useState(0);
  const [popover, setPopover] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  const [refOpen, setRefOpen] = useState(false);
  const [adding, setAdding] = useState(false);
  const [addingInPopover, setAddingInPopover] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const popoverInputRef = useRef<HTMLInputElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function onMouseDown(e: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setPopover(false);
        setHelpOpen(false);
        setAddingInPopover(false);
        setOpen(false);
        setInput("");
        setAdding(false);
      }
    }
    document.addEventListener("mousedown", onMouseDown);
    return () => document.removeEventListener("mousedown", onMouseDown);
  }, []);

  const VISIBLE = 2;
  const visibleTags = tags.slice(0, VISIBLE);
  const hiddenTags = tags.slice(VISIBLE);
  const showInput = tags.length === 0 || adding;
  const showSearchHelp = tags.length === 0 && input.trim() === "";

  const suggestions = useMemo(() => {
    if (!input.trim()) return [];
    const q = input.toLowerCase();
    return ALL_CHECK_IDS.filter(
      (s) => !tags.includes(s) && (s.includes(q) || (checkLabels[s] ?? "").toLowerCase().includes(q))
    ).slice(0, 8);
  }, [input, tags]);

  function commit(value: string) {
    const v = value.trim().replace(/,+$/, "");
    if (v && !tags.includes(v)) onTagsChange([...tags, v]);
    setInput("");
    setOpen(false);
    setHi(0);
    setAdding(false);
    setAddingInPopover(false);
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "," || e.key === "Enter" || e.key === "Tab") {
      e.preventDefault();
      commit(suggestions[hi] ?? input);
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      setHi((h) => Math.min(h + 1, suggestions.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setHi((h) => Math.max(h - 1, 0));
    } else if (e.key === "Backspace" && input === "" && tags.length > 0) {
      onTagsChange(tags.slice(0, -1));
    } else if (e.key === "Escape") {
      setOpen(false);
      setAdding(false);
      setAddingInPopover(false);
    }
  }

  return (
    <div className="relative" ref={containerRef}>
      {/* Main bar — left: chips+input scrollable, right: actions pinned */}
      <div className="flex items-center h-10 w-80 rounded-xl border border-zinc-200 bg-white shadow-sm transition focus-within:border-zinc-400 focus-within:ring-2 focus-within:ring-zinc-950/[0.06]">
        {/* Scrollable chips + input */}
        <div
          className="flex items-center gap-1.5 flex-1 min-w-0 h-full pl-3 overflow-hidden cursor-text"
          onClick={() => { setAdding(true); setTimeout(() => inputRef.current?.focus(), 0); }}
        >
          {visibleTags.map((tag) => (
            <span key={tag} className="inline-flex shrink-0 items-center gap-0.5 rounded-md bg-indigo-50 border border-indigo-200 px-2 py-0.5 text-xs font-mono text-indigo-700 max-w-[110px]">
              <span className="truncate">{tag}</span>
              <button type="button" className="ml-0.5 text-indigo-400 hover:text-indigo-700 leading-none shrink-0"
                onClick={(e) => { e.stopPropagation(); onTagsChange(tags.filter((t) => t !== tag)); }}>×</button>
            </span>
          ))}
          {showInput && (
            <input
              ref={inputRef}
              value={input}
              onChange={(e) => { setInput(e.target.value); setOpen(true); setHi(0); }}
              onKeyDown={handleKeyDown}
              onFocus={() => setOpen(true)}
              onBlur={() => { setTimeout(() => { setOpen(false); if (!input.trim()) setAdding(false); }, 150); }}
              placeholder={tags.length === 0 ? "Search findings…" : "Add filter…"}
              className="shrink-0 min-w-20 flex-1 text-sm text-zinc-800 outline-none bg-transparent placeholder:text-zinc-400"
            />
          )}
        </div>

        {/* Pinned right actions */}
        <div className="flex items-center gap-1 pr-2 shrink-0">
          {hiddenTags.length > 0 && (
            <button type="button"
              className="inline-flex items-center rounded-md bg-zinc-100 border border-zinc-200 px-2 py-0.5 text-xs font-semibold text-zinc-500 hover:bg-indigo-50 hover:border-indigo-200 hover:text-indigo-600 transition-colors"
              onClick={(e) => { e.stopPropagation(); setPopover((p) => !p); }}>
              +{hiddenTags.length}
            </button>
          )}
          {showSearchHelp && (
            <button
              type="button"
              aria-label="Search help"
              className="flex h-5 w-5 items-center justify-center rounded-full border border-zinc-200 bg-zinc-50 text-xs font-bold text-zinc-400 transition hover:border-indigo-200 hover:bg-indigo-50 hover:text-indigo-600"
              onClick={(e) => { e.stopPropagation(); setHelpOpen((p) => !p); setOpen(false); }}
            >
              ?
            </button>
          )}
          {tags.length > 0 && (
            <button type="button"
              className="text-zinc-300 hover:text-zinc-500 transition-colors text-base leading-none px-0.5"
              onClick={(e) => { e.stopPropagation(); onTagsChange([]); setAdding(false); setPopover(false); }}>
              ×
            </button>
          )}
        </div>
      </div>

      {helpOpen && showSearchHelp && (
        <div className="absolute right-0 z-20 mt-1 w-80 rounded-xl border border-zinc-200 bg-white p-3 text-left shadow-lg">
          <div className="text-xs font-semibold text-zinc-700">Search lookup</div>
          <p className="mt-1 text-xs leading-relaxed text-zinc-500">
            Search by check, resource, ARN, or resource family. Examples: <span className="font-mono text-zinc-700">iam.root</span>,{" "}
            <span className="font-mono text-zinc-700">s3.bucket</span>, <span className="font-mono text-zinc-700">ec2.instance</span>.
          </p>
          <button type="button" onClick={() => { setHelpOpen(false); setRefOpen(true); }} className="mt-3 inline-flex items-center text-xs font-semibold text-indigo-600 hover:text-indigo-700">
            Open search reference
            <svg className="ml-1 h-3 w-3" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
            </svg>
          </button>
        </div>
      )}

      {refOpen && <SearchReferenceModal onClose={() => setRefOpen(false)} />}

      {/* Overflow popover */}
      {popover && (
        <div className="absolute z-20 mt-1 left-0 rounded-xl border border-zinc-200 bg-white shadow-lg p-2 w-80">
          <div className="flex flex-wrap gap-1.5">
            {hiddenTags.map((tag) => (
              <span key={tag} className="inline-flex items-center gap-0.5 rounded-md bg-indigo-50 border border-indigo-200 px-2 py-0.5 text-xs font-mono text-indigo-700">
                {tag}
                <button type="button" className="ml-0.5 text-indigo-400 hover:text-indigo-700 leading-none"
                  onClick={() => { onTagsChange(tags.filter((t) => t !== tag)); if (hiddenTags.length <= 1) { setPopover(false); setAddingInPopover(false); } }}>×</button>
              </span>
            ))}
          </div>

          <div className="border-t border-zinc-100 mt-2 pt-2 relative">
            {addingInPopover ? (
              <>
                <input
                  ref={popoverInputRef}
                  value={input}
                  onChange={(e) => { setInput(e.target.value); setOpen(true); setHi(0); }}
                  onKeyDown={handleKeyDown}
                  onFocus={() => setOpen(true)}
                  onBlur={() => { setTimeout(() => { setOpen(false); if (!input.trim()) setAddingInPopover(false); }, 150); }}
                  placeholder="Type to add filter…"
                  className="w-full text-xs text-zinc-700 outline-none bg-transparent placeholder:text-zinc-400 pl-1"
                />
                {open && suggestions.length > 0 && (
                  <div className="absolute z-30 top-full left-0 right-0 mt-1 rounded-xl border border-zinc-200 bg-white shadow-lg overflow-hidden">
                    {suggestions.map((s, i) => (
                      <button key={s} type="button"
                        className={`w-full text-left px-3 py-2 flex items-center gap-2 transition-colors ${i === hi ? "bg-zinc-100" : "hover:bg-zinc-50"}`}
                        onMouseDown={() => commit(s)} onMouseEnter={() => setHi(i)}>
                        <span className="text-xs font-mono font-semibold text-zinc-700 shrink-0">{s}</span>
                        {checkLabels[s] && <span className="text-xs text-zinc-400 truncate">{checkLabels[s]}</span>}
                      </button>
                    ))}
                  </div>
                )}
              </>
            ) : (
              <button type="button"
                className="text-xs text-zinc-400 hover:text-indigo-600 transition-colors pl-1"
                onClick={() => { setAddingInPopover(true); setTimeout(() => popoverInputRef.current?.focus(), 0); }}>
                + Add filter…
              </button>
            )}
          </div>
        </div>
      )}

      {open && !addingInPopover && suggestions.length > 0 && (
        <div className="absolute z-20 mt-1 w-full min-w-80 rounded-xl border border-zinc-200 bg-white shadow-lg overflow-hidden">
          {suggestions.map((s, i) => (
            <button
              key={s}
              type="button"
              className={`w-full text-left px-3 py-2 flex items-center gap-2 transition-colors ${i === hi ? "bg-zinc-100" : "hover:bg-zinc-50"}`}
              onMouseDown={() => commit(s)}
              onMouseEnter={() => setHi(i)}
            >
              <span className="text-xs font-mono font-semibold text-zinc-700 shrink-0">{s}</span>
              {checkLabels[s] && <span className="text-xs text-zinc-400 truncate">{checkLabels[s]}</span>}
            </button>
          ))}
          <div className="px-3 py-1.5 border-t border-zinc-100 text-[10px] text-zinc-400">
            Tab / Enter / comma to add · Backspace to remove
          </div>
        </div>
      )}
    </div>
  );
}

export default function Findings() {
  const qc = useQueryClient();
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [scanTriggered, setScanTriggered] = useState(false);
  const [drawerResolved, setDrawerResolved] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [searchParams, setSearchParams] = useSearchParams();
  const [status, setStatus] = useState<StatusTab>("open");
  const [selected, setSelected] = useState<Finding | null>(null);
  const [sortKey, setSortKey] = useState<SortKey>("severity");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const [searchTags, setSearchTags] = useState<string[]>(() => {
    const raw = searchParams.get("checks");
    return raw ? raw.split(",").filter(Boolean) : [];
  });
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>(() => loadCollapsedGroups());

  function handleTagsChange(tags: string[]) {
    setSearchTags(tags);
    if (tags.length > 0) {
      setSearchParams({ checks: tags.join(",") }, { replace: true });
    } else {
      setSearchParams({}, { replace: true });
    }
  }
  const prevScanStatus = useRef<string | null>(null);

  useEffect(() => {
    localStorage.setItem(COLLAPSED_FINDINGS_KEY, JSON.stringify(collapsed));
  }, [collapsed]);

  const downloadCsv = useCallback(async () => {
    const BASE = (import.meta.env.VITE_API_URL as string) || "http://localhost:8000";
    const t = token();
    const res = await fetch(`${BASE}/v1/exports/findings.csv?status=${status}`, { headers: t ? { Authorization: `Bearer ${t}` } : {} });
    if (!res.ok) return;
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "vigil-findings.csv";
    a.click();
    URL.revokeObjectURL(url);
  }, [status]);

  const q = useQuery({
    queryKey: ["findings", status],
    queryFn: () => api<FindingPage>(`/v1/findings?status=${status}&limit=500`),
    refetchInterval: verifying ? 3000 : false,
  });
  const accounts = useQuery({ queryKey: ["accounts"], queryFn: () => api<Account[]>("/v1/accounts") });
  const connectedId = accounts.data?.find((a) => a.status === "connected")?.id;

  const scanRun = useQuery({
    queryKey: ["scan-run-latest", connectedId],
    queryFn: () => connectedId ? api<{ id: string; status: string; started_at: string; finished_at: string | null; error: string | null } | null>(`/v1/accounts/${connectedId}/scan-runs/latest`) : null,
    enabled: !!connectedId,
    refetchInterval: (query) => query.state.data?.status === "running" ? 5000 : false,
  });

  const scanStatus = scanRun.data?.status ?? null;
  const scanStartedAt = scanRun.data?.started_at ? new Date(scanRun.data.started_at) : null;
  const scanStuck = scanStartedAt ? Date.now() - scanStartedAt.getTime() > 5 * 60 * 1000 : false;
  const isRunning = scanStatus === "running" && !scanStuck;

  useEffect(() => {
    if (prevScanStatus.current === "running" && scanStatus === "ok") qc.invalidateQueries({ queryKey: ["findings"] });
    if (scanStatus === "running") setScanTriggered(false);
    prevScanStatus.current = scanStatus;
  }, [scanStatus, qc]);

  useEffect(() => {
    if (isRefreshing && !q.isFetching) {
      const t = setTimeout(() => setIsRefreshing(false), 600);
      return () => clearTimeout(t);
    }
  }, [q.isFetching, isRefreshing]);

  useEffect(() => {
    if (!selected || !q.data || drawerResolved) return;
    const still = q.data.items.find((f) => f.id === selected.id);
    if (!still) { setDrawerResolved(true); setVerifying(false); }
  }, [q.data, selected, drawerResolved]);

  const scan = useMutation({
    mutationFn: (id: string) => api(`/v1/accounts/${id}/scan`, { method: "POST" }),
    onSuccess: () => setTimeout(() => qc.invalidateQueries({ queryKey: ["scan-run-latest"] }), 300),
    onError: () => setScanTriggered(false),
  });
  const act = useMutation({
    mutationFn: ({ id, action }: { id: string; action: "recheck" | "resolve" | "ignore" }) =>
      api(`/v1/findings/${id}/${action}`, { method: "POST", body: JSON.stringify({}) }),
    onSuccess: (_data, { action }) => {
      if (action === "recheck") {
        setTimeout(() => qc.invalidateQueries({ queryKey: ["findings"] }), 6000);
        setTimeout(() => setVerifying(false), 40000);
      } else {
        qc.invalidateQueries({ queryKey: ["findings"] });
      }
    },
    onError: (_err, { action }) => {
      if (action === "recheck") setVerifying(false);
    },
  });

  const findings = q.data?.items ?? [];
  const totals = useMemo(() => {
    const t = { open: 0, critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of findings) {
      t.open++;
      if (f.severity in t) t[f.severity as keyof typeof t]++;
    }
    return t;
  }, [findings]);

  const rows = useMemo(() => {
    const arr = findings.filter((f) => {
      if (!matchesSeverityFilter(f, severityFilter)) return false;
      if (searchTags.length === 0) return true;
      // OR logic: finding matches any tag (exact check_id or text search)
      return searchTags.some((tag) => {
        if (f.check_id === tag) return true;
        const haystack = [f.title, f.check_id, f.resource_arn, checkLabels[f.check_id] ?? ""].join(" ").toLowerCase();
        return haystack.includes(tag.toLowerCase());
      });
    });
    arr.sort((a, b) => {
      let cmp = 0;
      if (sortKey === "severity") cmp = (sevWeight[a.severity] ?? 9) - (sevWeight[b.severity] ?? 9) || b.risk_score - a.risk_score;
      else if (sortKey === "score") cmp = b.risk_score - a.risk_score;
      else cmp = new Date(b.first_seen).getTime() - new Date(a.first_seen).getTime();
      return sortDir === "asc" ? cmp : -cmp;
    });
    return arr;
  }, [findings, searchTags, severityFilter, sortKey, sortDir]);

  const grouped = useMemo(() => {
    if (sortKey !== "severity" || status !== "open") return null;
    const map = new Map<string, Finding[]>();
    for (const f of rows) {
      const list = map.get(f.check_id) ?? [];
      list.push(f);
      map.set(f.check_id, list);
    }
    return [...map.entries()].sort(([, a], [, b]) => (sevWeight[a[0].severity] ?? 9) - (sevWeight[b[0].severity] ?? 9) || b.length - a.length);
  }, [rows, sortKey]);

  function toggleSort(k: SortKey) {
    if (sortKey === k) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else {
      setSortKey(k);
      setSortDir(k === "severity" ? "asc" : "desc");
    }
  }

  const pctOf = (n: number) => totals.open === 0 ? "—" : `${Math.round((n / totals.open) * 100)}% of open`;
  const chTotal = totals.critical + totals.high;
  const summaryCards = [
    { key: "all" as SeverityFilter, label: "Open", value: totals.open, tone: "text-zinc-900", hint: `${chTotal} crit/high · ${totals.medium} med · ${totals.low} low`, dot: "bg-zinc-400", glow: "" },
    { key: "critical_high" as SeverityFilter, label: "Critical · High", value: chTotal, tone: "text-red-600", hint: pctOf(chTotal), dot: "bg-red-500", glow: "bg-gradient-to-br from-red-50/60 to-white" },
    { key: "medium" as SeverityFilter, label: "Medium", value: totals.medium, tone: "text-amber-600", hint: pctOf(totals.medium), dot: "bg-amber-500", glow: "bg-gradient-to-br from-amber-50/50 to-white" },
    { key: "low" as SeverityFilter, label: "Low", value: totals.low, tone: "text-zinc-600", hint: pctOf(totals.low), dot: "bg-zinc-300", glow: "" },
  ];

  if (!accounts.isLoading && accounts.data && !connectedId) {
    return (
      <div className="flex h-full flex-col items-center justify-center px-8 py-20 text-center">
        <div className="mb-5 flex h-14 w-14 items-center justify-center rounded-2xl border border-zinc-200 bg-white shadow-sm">
          <svg className="h-7 w-7 text-zinc-400" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
          </svg>
        </div>
        <h2 className="mb-2 text-lg font-semibold text-zinc-900">No AWS account connected</h2>
        <p className="mb-6 max-w-sm text-sm text-zinc-500 leading-relaxed">
          Connect your AWS account to start scanning for security findings and generate compliance evidence.
        </p>
        <div className="mb-8 flex flex-col gap-3 text-left max-w-sm w-full">
          {[
            { step: "1", text: "Go to AWS Accounts and add your account" },
            { step: "2", text: "Launch the pre-filled CloudFormation stack" },
            { step: "3", text: "Paste the role ARN and verify — scan starts automatically" },
          ].map(({ step, text }) => (
            <div key={step} className="flex items-center gap-3 rounded-xl border border-zinc-100 bg-zinc-50 px-4 py-3">
              <span className="flex h-6 w-6 flex-shrink-0 items-center justify-center rounded-full bg-indigo-600 text-xs font-bold text-white">{step}</span>
              <span className="text-sm text-zinc-700">{text}</span>
            </div>
          ))}
        </div>
        <a href="/accounts" className="rounded-xl bg-indigo-600 px-5 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-700">
          Connect AWS account
        </a>
      </div>
    );
  }

  return (
    <div className="w-full px-8 py-7">
      <div className="mb-7 flex items-start justify-between gap-6">
        <div className="min-w-0">
          <h1 className="text-2xl font-bold tracking-tight text-zinc-950">Findings</h1>
          <p className="mt-1 text-sm text-zinc-500">Security posture issues from the latest account scan.{scanRun.data?.finished_at && <> Last scan {lastScanLabel(scanRun.data.finished_at)}.</>}</p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <button onClick={downloadCsv} className="rounded-xl border border-zinc-200 bg-white px-4 py-2.5 text-sm font-semibold text-zinc-600 shadow-sm transition hover:border-zinc-300 hover:bg-zinc-50 hover:text-zinc-950">Export</button>
          <button onClick={() => { if (isRefreshing) return; qc.invalidateQueries({ queryKey: ["findings"] }); setIsRefreshing(true); }} disabled={isRefreshing} className="inline-flex items-center gap-2 rounded-xl border border-zinc-200 bg-white px-4 py-2.5 text-sm font-semibold text-zinc-600 shadow-sm transition hover:border-zinc-300 hover:bg-zinc-50 hover:text-zinc-950 disabled:opacity-50 disabled:cursor-not-allowed">{isRefreshing && <svg className="h-3.5 w-3.5 animate-spin" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/></svg>}Refresh</button>
          {connectedId && <button onClick={() => { setScanTriggered(true); scan.mutate(connectedId); }} disabled={scanTriggered || isRunning} className="inline-flex items-center gap-2 rounded-xl bg-indigo-600 px-4 py-2.5 text-sm font-semibold text-white shadow-sm shadow-indigo-600/20 transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-50">{(scanTriggered || isRunning) && <svg className="h-3.5 w-3.5 animate-spin" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/></svg>}{isRunning ? "Scanning…" : scanTriggered ? "Starting…" : "Re-scan"}</button>}
        </div>
      </div>

      {isRunning && <div className="mb-4 inline-flex items-center gap-3 rounded-xl border border-indigo-100 bg-indigo-50 px-4 py-3 text-sm font-medium text-indigo-700"><svg className="h-3.5 w-3.5 flex-shrink-0 animate-spin opacity-70" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/></svg>Scan running — findings will refresh automatically on completion.</div>}
      {scanStatus === "error" && scanRun.data?.error && <div className="mb-4 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700"><span className="font-semibold">Last scan failed:</span> {scanRun.data.error}</div>}

      <div className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {summaryCards.map((card) => (
          <button
            key={card.key}
            onClick={() => setSeverityFilter(card.key)}
            className={`group relative overflow-hidden rounded-2xl border px-5 py-4 text-left shadow-sm shadow-zinc-950/[0.04] transition hover:-translate-y-0.5 hover:border-zinc-300 hover:shadow-md ${card.glow || "bg-white"} ${severityFilter === card.key ? "border-zinc-300 ring-4 ring-zinc-950/[0.04]" : "border-zinc-200"}`}
          >
            <div className="mb-3 flex items-center justify-between">
              <span className="text-[11px] font-semibold uppercase tracking-[0.14em] text-zinc-500">{card.label}</span>
              <span className={`h-2 w-2 rounded-full ${card.dot}`} />
            </div>
            <div className={`text-[2.75rem] font-bold tabular-nums leading-none tracking-tight ${card.tone}`}>{card.value}</div>
            <div className="mt-2.5 text-xs font-medium text-zinc-500 tabular-nums">{card.hint}</div>
          </button>
        ))}
      </div>

      <div className="mb-5 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex w-fit items-center gap-1 rounded-xl border border-zinc-200 bg-white p-1 shadow-sm shadow-zinc-950/[0.03]">{statusTabs.map((s) => <button key={s} onClick={() => setStatus(s)} className={`rounded-lg px-4 py-2 text-sm font-semibold capitalize transition-all ${status === s ? "bg-zinc-950 text-white shadow-sm" : "text-zinc-500 hover:bg-zinc-50 hover:text-zinc-900"}`}>{s}</button>)}</div>
        <div className="flex items-center gap-2">
          <TagSearchInput tags={searchTags} onTagsChange={handleTagsChange} />
          <div className="flex h-10 items-center gap-0.5 rounded-xl border border-zinc-200 bg-white px-1.5 shadow-sm">{(["severity", "score", "first_seen"] as SortKey[]).map((k) => <button key={k} onClick={() => toggleSort(k)} className={`inline-flex h-7 items-center gap-1 rounded-lg px-3 text-sm font-medium transition-all ${sortKey === k ? "bg-zinc-100 text-zinc-950 font-semibold" : "text-zinc-400 hover:bg-zinc-50 hover:text-zinc-700"}`}>{sortLabel(k)}{sortKey === k && <span className="text-xs text-zinc-500">{sortIcon(k, sortKey, sortDir)}</span>}</button>)}</div>
        </div>
      </div>

      {q.isLoading && <div className="rounded-2xl border border-zinc-200 bg-white px-4 py-16 text-center text-sm text-zinc-400">Loading…</div>}
      {!q.isLoading && rows.length === 0 && <div className="rounded-2xl border border-zinc-200 bg-white px-4 py-16 text-center"><p className="text-sm font-semibold text-zinc-700">No {status} findings</p><p className="mt-1 text-sm text-zinc-400">{status === "open" ? "Run a scan to check your account for IAM issues." : "Nothing to show here."}</p></div>}

      {rows.length > 0 && (
        <div className="space-y-2.5 pb-8">
          {(grouped ?? [["all", rows] as [string, Finding[]]]).map(([key, items]) => {
            const isGrouped = grouped !== null;
            const sev = items[0]?.severity ?? "low";
            const label = checkLabels[key] ?? key;
            const description = checkDescriptions[key];
            const isCollapsed = !!collapsed[key];
            return (
              <div
                key={key}
                className="overflow-hidden rounded-2xl border border-zinc-200 bg-white shadow-sm shadow-zinc-950/[0.04] transition-shadow hover:border-zinc-300 hover:shadow-md"
              >
                {isGrouped && (
                  <button
                    type="button"
                    onClick={() => setCollapsed((prev) => ({ ...prev, [key]: !prev[key] }))}
                    className="grid w-full grid-cols-[auto_auto_minmax(0,1fr)_44px_44px] items-center gap-3 bg-gradient-to-r from-zinc-50/80 to-white pl-5 pr-3 py-3.5 text-left transition-colors hover:from-zinc-100/60"
                  >
                    <svg
                      className={`h-3.5 w-3.5 transition-transform duration-150 ${isCollapsed ? "-rotate-90 text-zinc-600" : "text-zinc-500"}`}
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                    </svg>
                    <span className={`inline-block w-[72px] text-center rounded border py-0.5 text-[10px] font-semibold uppercase tracking-[0.12em] ${sevBadge[sev] ?? sevBadge.low}`}>
                      {sev}
                    </span>
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-[15px] font-semibold text-zinc-900">{label}</span>
                        <span className="rounded-full bg-zinc-100 px-2 py-0.5 text-[11px] font-semibold tabular-nums text-zinc-500">
                          {items.length}
                        </span>
                      </div>
                      {description && (
                        <p className="mt-0.5 text-xs font-medium text-zinc-600 leading-normal">{description}</p>
                      )}
                    </div>
                    <span className="hidden text-center text-[10px] font-semibold uppercase tracking-[0.1em] text-zinc-500 md:block">Score</span>
                    <span className="hidden text-center text-[10px] font-semibold uppercase tracking-[0.1em] text-zinc-500 md:block">Age</span>
                  </button>
                )}

                {/* Animated accordion — CSS grid-template-rows transition */}
                <div
                  className="grid transition-[grid-template-rows] duration-[140ms] ease-out"
                  style={{ gridTemplateRows: isCollapsed ? "0fr" : "1fr" }}
                >
                  <div className="overflow-hidden">
                    <div className={`divide-y divide-zinc-100 ${isGrouped ? `border-t border-zinc-100 ${sevExpandedBg[sev] ?? sevExpandedBg.low} ${sevAccent[sev] ?? ""}` : ""}`}>
                      {items.map((f) => (
                        <div
                          key={f.id}
                          onClick={() => setSelected(f)}
                          className={`group grid cursor-pointer grid-cols-[minmax(0,1fr)_44px_44px] items-center gap-3 py-2.5 pr-3 transition-colors duration-[120ms] hover:bg-zinc-100/50 ${isGrouped ? "pl-10" : "pl-5"}`}
                        >
                          <div className="min-w-0">
                            <div className="truncate text-sm font-medium text-zinc-700 transition-colors group-hover:text-zinc-900">
                              {resourceName(f.resource_arn)}
                            </div>
                            {!isGrouped && description && (
                              <p className="mt-0.5 truncate text-xs text-zinc-600">{description}</p>
                            )}
                          </div>
                          <div className="flex justify-center">
                            <span className="text-xs font-medium tabular-nums text-zinc-500">
                              {f.risk_score}
                            </span>
                          </div>
                          <div className="text-center">
                            <span className="text-xs font-medium tabular-nums text-zinc-500">{daysAgo(f.first_seen)}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      <FindingDrawer
        finding={selected}
        accountId={connectedId ?? null}
        resolved={drawerResolved}
        verifying={verifying}
        onClose={() => { setSelected(null); setDrawerResolved(false); setVerifying(false); }}
        onAction={(id, action) => {
          if (action === "recheck") setVerifying(true);
          act.mutate({ id, action });
        }}
      />
    </div>
  );
}
