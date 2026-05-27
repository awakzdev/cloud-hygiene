type CfnPermissionsBannerProps = {
  cfnLaunchUrl?: string | null;
  className?: string;
};

export default function CfnPermissionsBanner({ cfnLaunchUrl, className }: CfnPermissionsBannerProps) {
  return (
    <div
      className={`rounded-xl border border-amber-200 bg-amber-50/90 px-4 py-3 text-sm text-amber-950 ${className ?? ""}`}
      role="status"
    >
      <p className="font-semibold">CloudFormation stack may be out of date</p>
      <p className="mt-1 text-xs leading-relaxed text-amber-900/90">
        The latest scan collected no data from newer AWS services (Lambda, DynamoDB, ACM, and others). Update the
        read-only role stack in your AWS account, then re-scan — otherwise gap checks and least-privilege data stay empty.
      </p>
      {cfnLaunchUrl && (
        <a
          href={cfnLaunchUrl}
          target="_blank"
          rel="noreferrer"
          className="mt-2 inline-flex items-center gap-1 text-xs font-semibold text-amber-900 underline decoration-amber-400 underline-offset-2 hover:text-amber-950"
        >
          Update CloudFormation stack
          <svg className="h-3 w-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
          </svg>
        </a>
      )}
    </div>
  );
}
