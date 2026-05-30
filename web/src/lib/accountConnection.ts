/** Account is usable (connected, or failed re-verify on an established account). */
export function isAccountConnected(acc: {
  status: string;
  account_id: string | null;
}): boolean {
  return acc.status === "connected" || (acc.status === "error" && !!acc.account_id);
}
