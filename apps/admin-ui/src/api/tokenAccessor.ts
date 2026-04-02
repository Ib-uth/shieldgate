/** Module-level hooks for axios interceptors (avoids circular imports with AuthContext). */

let getAccessTokenImpl: () => string | null = () => null;

export function setAccessTokenGetter(fn: () => string | null): void {
  getAccessTokenImpl = fn;
}

export function getAccessToken(): string | null {
  return getAccessTokenImpl();
}

let applyAccessTokenImpl: (token: string) => void = () => {};

/** Called from AuthProvider so refresh can update React state + sessionStorage. */
export function setAccessTokenUpdater(fn: (token: string) => void): void {
  applyAccessTokenImpl = fn;
}

export function applyRefreshedAccessToken(token: string): void {
  applyAccessTokenImpl(token);
}

let onUnauthorized: (() => void) | null = null;

export function setUnauthorizedHandler(fn: (() => void) | null): void {
  onUnauthorized = fn;
}

export function triggerUnauthorized(): void {
  onUnauthorized?.();
}
