/** Helpers for What If / blast radius presentation */

export type BlastRadiusService = {
  name: string;
  last_used: string | null;
  days_ago: number | null;
  active: boolean;
  in_policy: boolean;
};

export type ServiceUsageBuckets = {
  recentlyActive: BlastRadiusService[];
  historicallyUsed: BlastRadiusService[];
  likelySafe: BlastRadiusService[];
};

const RECENT_DAYS = 30;
const HISTORICAL_MAX_DAYS = 90;

export function bucketServicesByUsage(services: BlastRadiusService[]): ServiceUsageBuckets {
  const recentlyActive: BlastRadiusService[] = [];
  const historicallyUsed: BlastRadiusService[] = [];
  const likelySafe: BlastRadiusService[] = [];

  for (const s of services) {
    if (s.days_ago === null || s.days_ago > HISTORICAL_MAX_DAYS) {
      likelySafe.push(s);
    } else if (s.days_ago <= RECENT_DAYS) {
      recentlyActive.push(s);
    } else {
      historicallyUsed.push(s);
    }
  }

  const byDays = (a: BlastRadiusService, b: BlastRadiusService) =>
    (a.days_ago ?? 999) - (b.days_ago ?? 999);

  recentlyActive.sort(byDays);
  historicallyUsed.sort(byDays);
  likelySafe.sort((a, b) => a.name.localeCompare(b.name));

  return { recentlyActive, historicallyUsed, likelySafe };
}

export function formatServiceLastUsed(daysAgo: number | null): string {
  if (daysAgo === null) return "No recorded use";
  if (daysAgo === 0) return "Today";
  if (daysAgo === 1) return "Yesterday";
  if (daysAgo < 30) return `${daysAgo} days ago`;
  if (daysAgo < 365) return `${Math.floor(daysAgo / 30)} mo ago`;
  return `${Math.floor(daysAgo / 365)} yr ago`;
}
