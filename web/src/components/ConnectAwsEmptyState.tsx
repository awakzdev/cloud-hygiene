const SETUP_STEPS = [
  { step: "1", text: "Go to AWS Accounts and add your account" },
  { step: "2", text: "Launch the CloudFormation stack" },
  { step: "3", text: "Paste the role ARN and verify — scan starts automatically" },
] as const;

export default function ConnectAwsEmptyState() {
  return (
    <div className="flex h-full flex-col items-center justify-center px-8 py-20 text-center">
      <div className="mb-5 flex h-14 w-14 items-center justify-center rounded-2xl border border-zinc-200 bg-white shadow-sm">
        <svg className="h-7 w-7 text-zinc-400" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24">
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"
          />
        </svg>
      </div>
      <h2 className="mb-2 text-lg font-semibold text-zinc-900">No AWS account connected</h2>
      <p className="mb-6 max-w-sm text-sm leading-relaxed text-zinc-500">
        Connect your AWS account to start scanning for security findings and generate compliance evidence.
      </p>
      <div className="mb-8 flex w-full max-w-sm flex-col gap-3 text-left">
        {SETUP_STEPS.map(({ step, text }) => (
          <div
            key={step}
            className="flex items-center gap-3 rounded-xl border border-zinc-100 bg-zinc-50 px-4 py-3"
          >
            <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-indigo-600 text-xs font-bold text-white">
              {step}
            </span>
            <span className="text-sm text-zinc-700">{text}</span>
          </div>
        ))}
      </div>
      <a
        href="/accounts"
        className="rounded-xl bg-indigo-600 px-5 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-700"
      >
        Connect AWS account
      </a>
    </div>
  );
}
