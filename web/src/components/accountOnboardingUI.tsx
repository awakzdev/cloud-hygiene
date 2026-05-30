import { useState } from "react";

export function DeploymentParametersCard({ externalId }: { externalId: string }) {
  const [copied, setCopied] = useState(false);

  async function copyExternalId() {
    await navigator.clipboard.writeText(externalId);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="rounded-lg border border-zinc-200/80 bg-white px-4 py-3 shadow-sm">
      <p className="text-xs font-semibold text-zinc-900">Deployment parameters</p>
      <dl className="mt-3 space-y-2.5 text-sm">
        <div className="grid grid-cols-[7.5rem_minmax(0,1fr)_auto] items-center gap-x-3 gap-y-1">
          <dt className="text-xs font-medium text-zinc-500">External ID</dt>
          <dd className="truncate font-mono text-xs text-zinc-800" title={externalId}>
            {externalId}
          </dd>
          <dd>
            <button
              type="button"
              onClick={copyExternalId}
              className={`rounded-md px-2 py-0.5 text-xs font-semibold transition ${
                copied
                  ? "text-emerald-700"
                  : "text-indigo-600 hover:bg-indigo-50 hover:text-indigo-800"
              }`}
            >
              {copied ? "Copied" : "Copy"}
            </button>
          </dd>
        </div>
      </dl>
    </div>
  );
}
