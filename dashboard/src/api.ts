// Talks to internal/api's 5 read-only endpoints (ADR 0011) using a
// bearer token the operator pastes in on the Settings page (ADR 0012 /
// 0013: no token-issuance UI here — tokens come from `riskforge token
// create`). The token lives in localStorage only; it is never sent
// anywhere but the Authorization header of these requests.

const TOKEN_STORAGE_KEY = "riskforge.token";

export function getToken(): string {
  try {
    return localStorage.getItem(TOKEN_STORAGE_KEY) ?? "";
  } catch {
    return "";
  }
}

export function setToken(token: string): void {
  try {
    if (token) {
      localStorage.setItem(TOKEN_STORAGE_KEY, token);
    } else {
      localStorage.removeItem(TOKEN_STORAGE_KEY);
    }
  } catch {
    // localStorage can throw (private browsing, disabled storage); the
    // token simply won't persist across reloads in that case.
  }
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

// fetchList calls one of the 5 GET /api/v1/<resource> endpoints and
// returns its JSON array. A 401/403 surfaces as an ApiError so callers
// can prompt for a token on the Settings page instead of showing a raw
// error.
export async function fetchList<T>(resource: string): Promise<T[]> {
  const token = getToken();
  const res = await fetch(`/api/v1/${resource}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });

  if (!res.ok) {
    let message = `request failed with status ${res.status}`;
    try {
      const body = (await res.json()) as { error?: string };
      if (body.error) message = body.error;
    } catch {
      // response body wasn't JSON; keep the generic message
    }
    throw new ApiError(res.status, message);
  }

  return (await res.json()) as T[];
}
