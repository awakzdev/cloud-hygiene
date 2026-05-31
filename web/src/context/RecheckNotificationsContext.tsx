import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api";

const STORAGE_KEY = "vigil.recheckNotifications.v3";
const HISTORY_LIMIT = 100;
/** Max wait after Verify (queued full recheck or stuck pending state). */
export const RECHECK_TIMEOUT_MS = 30_000;
const CLOUDTRAIL_POLL_MS = 30_000;
const CLOUDTRAIL_MAX_MS = 25 * 60 * 1000;

export type VerifyNotification = {
  id: string;
  kind: "verify";
  findingId: string;
  checkId: string;
  status: "verified" | "unchanged";
  completedAt: number;
  readAt?: number;
};

export type CloudTrailNotification = {
  id: string;
  kind: "cloudtrail";
  findingId: string;
  accountId: string;
  roleArn: string;
  roleLabel: string;
  status: "running" | "succeeded" | "failed";
  completedAt: number;
  readAt?: number;
  message?: string;
};

export type NotificationItem = VerifyNotification | CloudTrailNotification;

/** @deprecated Use VerifyNotification — kept for drawer verify flash typing */
export type RecheckOutcome = VerifyNotification;

export type PendingRecheck = {
  findingId: string;
  checkId: string;
  startedAt: number;
};

type PendingCloudTrail = {
  notificationId: string;
  findingId: string;
  accountId: string;
  roleArn: string;
  startedAt: number;
};

/** POST /v1/findings/{id}/recheck — fast path (checked) or async Celery (queued). */
export type RecheckResponse = {
  check_id?: string;
  finding_id?: string;
  queued?: boolean;
  checked?: boolean;
  resolved?: boolean;
  reason?: string;
  error?: string;
};

type PersistedV3 = {
  pendingRecheck: PendingRecheck | null;
  pendingCloudTrail: PendingCloudTrail | null;
  history: NotificationItem[];
};

type PersistedV2 = {
  pending: PendingRecheck | null;
  history: Omit<VerifyNotification, "kind">[];
};

type PersistedLegacy = {
  pending: PendingRecheck | null;
  outcome: Omit<VerifyNotification, "id" | "kind"> | null;
};

type FindingPage = { items: { id: string }[] };

type PolicyGenStatusRow = { status?: string; job_id?: string };

function newNotificationId(): string {
  return crypto.randomUUID();
}

export function roleLabelFromArn(roleArn: string): string {
  const slash = roleArn.lastIndexOf("/");
  return slash >= 0 ? roleArn.slice(slash + 1) : roleArn;
}

function isTerminalPolicyGenStatus(status: string | undefined): boolean {
  const s = (status ?? "").toUpperCase();
  return s === "SUCCEEDED" || s === "FAILED" || s === "CANCELLED" || s === "TIMED_OUT";
}

function migrateLegacyV1(raw: string): PersistedV3 {
  try {
    const parsed = JSON.parse(raw) as PersistedLegacy;
    const history: NotificationItem[] = [];
    if (parsed.outcome) {
      history.push({ ...parsed.outcome, id: newNotificationId(), kind: "verify" });
    }
    return { pendingRecheck: parsed.pending ?? null, pendingCloudTrail: null, history };
  } catch {
    return { pendingRecheck: null, pendingCloudTrail: null, history: [] };
  }
}

function migrateV2(raw: string): PersistedV3 {
  try {
    const parsed = JSON.parse(raw) as PersistedV2;
    const history: NotificationItem[] = (parsed.history ?? []).map((h) => ({
      ...h,
      kind: "verify" as const,
    }));
    return {
      pendingRecheck: parsed.pending ?? null,
      pendingCloudTrail: null,
      history,
    };
  } catch {
    return { pendingRecheck: null, pendingCloudTrail: null, history: [] };
  }
}

function loadPersisted(): PersistedV3 & { latestVerifyOutcome: VerifyNotification | null } {
  try {
    let state: PersistedV3 = { pendingRecheck: null, pendingCloudTrail: null, history: [] };

    const v3 = localStorage.getItem(STORAGE_KEY);
    if (v3) {
      const parsed = JSON.parse(v3) as PersistedV3;
      state = {
        pendingRecheck: parsed.pendingRecheck ?? null,
        pendingCloudTrail: parsed.pendingCloudTrail ?? null,
        history: Array.isArray(parsed.history) ? parsed.history : [],
      };
    } else {
      const v2 = localStorage.getItem("vigil.recheckNotifications.v2");
      if (v2) {
        state = migrateV2(v2);
      } else {
        const v1 = localStorage.getItem("vigil.recheckNotifications.v1");
        if (v1) state = migrateLegacyV1(v1);
      }
    }

    let latestVerifyOutcome: VerifyNotification | null = null;
    for (const item of state.history) {
      if (item.kind === "verify") {
        latestVerifyOutcome = item;
        break;
      }
    }

    if (state.pendingRecheck && Date.now() - state.pendingRecheck.startedAt >= RECHECK_TIMEOUT_MS) {
      const timedOut: VerifyNotification = {
        id: newNotificationId(),
        kind: "verify",
        findingId: state.pendingRecheck.findingId,
        checkId: state.pendingRecheck.checkId,
        status: "unchanged",
        completedAt: Date.now(),
      };
      state.history = [timedOut, ...state.history].slice(0, HISTORY_LIMIT);
      latestVerifyOutcome = timedOut;
      state.pendingRecheck = null;
    }

    return { ...state, latestVerifyOutcome };
  } catch {
    return { pendingRecheck: null, pendingCloudTrail: null, history: [], latestVerifyOutcome: null };
  }
}

function savePersisted(state: PersistedV3) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  } catch {
    /* ignore */
  }
}

function pushHistory(history: NotificationItem[], entry: NotificationItem): NotificationItem[] {
  return [entry, ...history.filter((h) => h.id !== entry.id)].slice(0, HISTORY_LIMIT);
}

type RecheckNotificationsContextValue = {
  pendingRecheck: PendingRecheck | null;
  pendingCloudTrail: PendingCloudTrail | null;
  recheckOutcome: VerifyNotification | null;
  notificationHistory: NotificationItem[];
  notificationCount: number;
  startRecheck: (findingId: string, checkId: string) => void;
  applyRecheckResult: (findingId: string, checkId: string, result: RecheckResponse) => boolean;
  completeRecheck: (outcome: Omit<VerifyNotification, "completedAt" | "id" | "readAt" | "kind">) => void;
  failRecheck: (findingId: string, checkId: string) => void;
  startCloudTrailAnalysis: (args: {
    findingId: string;
    accountId: string;
    roleArn: string;
    message?: string;
  }) => void;
  failCloudTrailAnalysis: (args: {
    findingId: string;
    accountId: string;
    roleArn: string;
    message: string;
  }) => void;
  clearDrawerVerifyFlash: () => void;
  dismissNotification: (id: string) => void;
  clearAll: () => void;
};

const RecheckNotificationsContext = createContext<RecheckNotificationsContextValue | null>(null);

export function RecheckNotificationsProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const initial = loadPersisted();
  const [pendingRecheck, setPendingRecheck] = useState<PendingRecheck | null>(initial.pendingRecheck);
  const [pendingCloudTrail, setPendingCloudTrail] = useState<PendingCloudTrail | null>(
    initial.pendingCloudTrail,
  );
  const [notificationHistory, setNotificationHistory] = useState<NotificationItem[]>(initial.history);
  const [recheckOutcome, setRecheckOutcome] = useState<VerifyNotification | null>(initial.latestVerifyOutcome);

  useEffect(() => {
    savePersisted({ pendingRecheck, pendingCloudTrail, history: notificationHistory });
  }, [pendingRecheck, pendingCloudTrail, notificationHistory]);

  const recordVerifyOutcome = useCallback(
    (outcome: Omit<VerifyNotification, "completedAt" | "id" | "readAt" | "kind">) => {
      const entry: VerifyNotification = {
        ...outcome,
        kind: "verify",
        id: newNotificationId(),
        completedAt: Date.now(),
      };
      setNotificationHistory((prev) => pushHistory(prev, entry));
      setRecheckOutcome(entry);
      setPendingRecheck(null);
      return entry;
    },
    [],
  );

  const finishCloudTrail = useCallback(
    (notificationId: string, status: "succeeded" | "failed", message?: string) => {
      setNotificationHistory((prev) =>
        prev.map((item) =>
          item.id === notificationId && item.kind === "cloudtrail"
            ? { ...item, status, completedAt: Date.now(), message: message ?? item.message }
            : item,
        ),
      );
      setPendingCloudTrail(null);
      void qc.invalidateQueries({ queryKey: ["generated-policy"] });
    },
    [qc],
  );

  const startCloudTrailAnalysis = useCallback(
    ({ findingId, accountId, roleArn, message }: {
      findingId: string;
      accountId: string;
      roleArn: string;
      message?: string;
    }) => {
      const id = newNotificationId();
      const entry: CloudTrailNotification = {
        id,
        kind: "cloudtrail",
        findingId,
        accountId,
        roleArn,
        roleLabel: roleLabelFromArn(roleArn),
        status: "running",
        completedAt: Date.now(),
        message,
      };
      setNotificationHistory((prev) => pushHistory(prev, entry));
      setPendingCloudTrail({
        notificationId: id,
        findingId,
        accountId,
        roleArn,
        startedAt: Date.now(),
      });
    },
    [],
  );

  const failCloudTrailAnalysis = useCallback(
    ({ findingId, accountId, roleArn, message }: {
      findingId: string;
      accountId: string;
      roleArn: string;
      message: string;
    }) => {
      const entry: CloudTrailNotification = {
        id: newNotificationId(),
        kind: "cloudtrail",
        findingId,
        accountId,
        roleArn,
        roleLabel: roleLabelFromArn(roleArn),
        status: "failed",
        completedAt: Date.now(),
        message,
      };
      setNotificationHistory((prev) => pushHistory(prev, entry));
      setPendingCloudTrail(null);
    },
    [],
  );

  const openMetricsQ = useQuery({
    queryKey: ["findings", "open"],
    queryFn: () => api<FindingPage>("/v1/findings?status=open&limit=500"),
    refetchInterval: pendingRecheck ? 3000 : false,
    enabled: !!pendingRecheck,
  });

  const startRecheck = useCallback((findingId: string, checkId: string) => {
    setPendingRecheck({ findingId, checkId, startedAt: Date.now() });
    setRecheckOutcome(null);
  }, []);

  const applyRecheckResult = useCallback(
    (findingId: string, checkId: string, result: RecheckResponse): boolean => {
      if (!result.checked) {
        return false;
      }
      recordVerifyOutcome({
        findingId,
        checkId: result.check_id ?? checkId,
        status: result.resolved ? "verified" : "unchanged",
      });
      void qc.invalidateQueries({ queryKey: ["findings"] });
      return true;
    },
    [qc, recordVerifyOutcome],
  );

  const completeRecheck = useCallback(
    (outcome: Omit<VerifyNotification, "completedAt" | "id" | "readAt" | "kind">) => {
      recordVerifyOutcome(outcome);
    },
    [recordVerifyOutcome],
  );

  const failRecheck = useCallback(
    (findingId: string, checkId: string) => {
      recordVerifyOutcome({ findingId, checkId, status: "unchanged" });
    },
    [recordVerifyOutcome],
  );

  const clearDrawerVerifyFlash = useCallback(() => {
    setRecheckOutcome(null);
  }, []);

  const dismissNotification = useCallback((id: string) => {
    const now = Date.now();
    setNotificationHistory((prev) =>
      prev.map((item) => (item.id === id ? { ...item, readAt: item.readAt ?? now } : item)),
    );
    setRecheckOutcome((prev) => (prev?.id === id ? { ...prev, readAt: now } : prev));
  }, []);

  const clearAll = useCallback(() => {
    setPendingRecheck(null);
    setPendingCloudTrail(null);
    setRecheckOutcome(null);
    setNotificationHistory([]);
  }, []);

  useEffect(() => {
    if (!pendingRecheck) return;
    const { findingId, checkId, startedAt } = pendingRecheck;

    const tick = () => {
      const elapsed = Date.now() - startedAt;
      if (elapsed >= RECHECK_TIMEOUT_MS) {
        completeRecheck({ findingId, checkId, status: "unchanged" });
        return;
      }
      const items = openMetricsQ.data?.items;
      if (items && !items.some((f) => f.id === findingId)) {
        completeRecheck({ findingId, checkId, status: "verified" });
        void qc.invalidateQueries({ queryKey: ["findings"] });
      }
    };

    tick();
    const interval = window.setInterval(tick, 1000);
    return () => window.clearInterval(interval);
  }, [pendingRecheck, openMetricsQ.data, completeRecheck, qc]);

  useEffect(() => {
    if (!pendingCloudTrail) return;
    const { notificationId, accountId, roleArn, startedAt } = pendingCloudTrail;

    const poll = async () => {
      if (Date.now() - startedAt >= CLOUDTRAIL_MAX_MS) {
        finishCloudTrail(notificationId, "failed", "Timed out waiting for AWS (~25 min).");
        return;
      }
      try {
        const row = await api<PolicyGenStatusRow>(
          `/v1/accounts/${accountId}/roles/policy-generation/status?role_arn=${encodeURIComponent(roleArn)}`,
        );
        const st = (row.status ?? "").toUpperCase();
        if (st === "SUCCEEDED") {
          finishCloudTrail(
            notificationId,
            "succeeded",
            "Analysis complete — rebuild suggestion to apply resource ARNs.",
          );
          return;
        }
        if (isTerminalPolicyGenStatus(row.status)) {
          finishCloudTrail(notificationId, "failed", `Analysis ended (${st}).`);
        }
      } catch {
        /* transient — keep polling */
      }
    };

    void poll();
    const interval = window.setInterval(() => void poll(), CLOUDTRAIL_POLL_MS);
    return () => window.clearInterval(interval);
  }, [pendingCloudTrail, finishCloudTrail]);

  const notificationCount =
    (pendingRecheck ? 1 : 0) +
    (pendingCloudTrail ? 1 : 0) +
    notificationHistory.filter(
      (h) =>
        !h.readAt &&
        !(
          h.kind === "cloudtrail" &&
          h.status === "running" &&
          pendingCloudTrail?.notificationId === h.id
        ),
    ).length;

  const value = useMemo(
    () => ({
      pendingRecheck,
      pendingCloudTrail,
      recheckOutcome,
      notificationHistory,
      notificationCount,
      startRecheck,
      applyRecheckResult,
      completeRecheck,
      failRecheck,
      startCloudTrailAnalysis,
      failCloudTrailAnalysis,
      clearDrawerVerifyFlash,
      dismissNotification,
      clearAll,
    }),
    [
      pendingRecheck,
      pendingCloudTrail,
      recheckOutcome,
      notificationHistory,
      notificationCount,
      startRecheck,
      applyRecheckResult,
      completeRecheck,
      failRecheck,
      startCloudTrailAnalysis,
      failCloudTrailAnalysis,
      clearDrawerVerifyFlash,
      dismissNotification,
      clearAll,
    ],
  );

  return (
    <RecheckNotificationsContext.Provider value={value}>{children}</RecheckNotificationsContext.Provider>
  );
}

export function useRecheckNotifications() {
  const ctx = useContext(RecheckNotificationsContext);
  if (!ctx) {
    throw new Error("useRecheckNotifications must be used within RecheckNotificationsProvider");
  }
  return ctx;
}
