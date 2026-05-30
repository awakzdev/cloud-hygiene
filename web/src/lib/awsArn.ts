/** IAM role ARN: arn:aws:iam::<12-digit account>:role/<name or path/name> */
export const IAM_ROLE_ARN_RE =
  /^arn:aws:iam::\d{12}:role\/[\w+=,.@\-/]+$/;

export function isValidIamRoleArn(value: string): boolean {
  return IAM_ROLE_ARN_RE.test(value.trim());
}
