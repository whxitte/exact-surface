"use client";

const TOKEN_KEY = "vantari_token";
const TENANT_KEY = "vantari_tenant";

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(TOKEN_KEY);
}

export function getTenant(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(TENANT_KEY);
}

export function setSession(token: string, tenantId: string) {
  window.localStorage.setItem(TOKEN_KEY, token);
  window.localStorage.setItem(TENANT_KEY, tenantId);
}

export function clearSession() {
  window.localStorage.removeItem(TOKEN_KEY);
  window.localStorage.removeItem(TENANT_KEY);
}

export function isAuthed(): boolean {
  return !!getToken();
}
