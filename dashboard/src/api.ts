// Talks to internal/api's endpoints (ADR 0011 read-only, ADR 0014
// Exception write) using a bearer token the operator pastes in on the
// Settings page (ADR 0012 / 0013: no token-issuance UI here — tokens
// come from `riskforge token create`). The token lives in localStorage
// only; it is never sent anywhere but the Authorization header of these
// requests.

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

// handleResponse turns a non-2xx response into an ApiError carrying
// internal/api's own {"error": "..."} message when present, shared by
// every call below so a 401/403 always looks the same to callers (who
// can then point the user at the Settings page).
async function handleResponse<T>(res: Response): Promise<T> {
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
  return (await res.json()) as T;
}

// fetchList calls one of the 5 GET /api/v1/<resource> endpoints and
// returns its JSON array.
export async function fetchList<T>(resource: string): Promise<T[]> {
  const token = getToken();
  const res = await fetch(`/api/v1/${resource}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  return handleResponse<T[]>(res);
}

// postAction calls one of the Exception write endpoints (ADR 0014) —
// POST /api/v1/exceptions or POST /api/v1/exceptions/{id}/{action} —
// and returns the updated (or newly created) resource.
export async function postAction<T>(path: string, body?: unknown): Promise<T> {
  const token = getToken();
  const res = await fetch(`/api/v1/${path}`, {
    method: "POST",
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  return handleResponse<T>(res);
}
