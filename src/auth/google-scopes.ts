export const IDENTITY_SCOPES = ["openid", "email", "profile"] as const;
export const CALENDAR_SCOPES: readonly string[] = [
  "https://www.googleapis.com/auth/calendar.events",
  "https://www.googleapis.com/auth/calendar.calendarlist.readonly",
];

const SCOPE_ALIASES = new Map([
  ...[...IDENTITY_SCOPES, ...CALENDAR_SCOPES].map((scope) => [scope, scope] as const),
  ["https://www.googleapis.com/auth/userinfo.email", "email"],
  ["https://www.googleapis.com/auth/userinfo.profile", "profile"],
]);

export function normalizeGoogleScopes(
  scopes: readonly unknown[],
  requiredCalendarScopes: readonly string[] = CALENDAR_SCOPES,
): readonly string[] {
  if (scopes.length === 0 || scopes.length > 100) throw new TypeError("Invalid Google scopes");
  const effective = new Set<string>();
  for (const scope of scopes) {
    const canonical = typeof scope === "string" ? SCOPE_ALIASES.get(scope) : undefined;
    if (canonical === undefined) throw new TypeError("Invalid Google scope");
    effective.add(canonical);
  }
  if ([...IDENTITY_SCOPES, ...requiredCalendarScopes].some((scope) => !effective.has(scope))) {
    throw new TypeError("Missing Google scope");
  }
  return [...effective];
}
