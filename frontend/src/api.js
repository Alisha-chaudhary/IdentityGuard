const API_BASE = import.meta.env.VITE_API_URL || "";

export async function login(username, password) {
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) throw new Error("Login failed");
  return res.json();
}

export async function fetchReport(path, token) {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
    },
  });

  if (response.status === 401) {
    const error = new Error("Your session has expired. Please sign in again.");
    error.status = 401;
    throw error;
  }

  if (response.status === 403) {
    const error = new Error("You do not have permission to view this report.");
    error.status = 403;
    throw error;
  }

  if (!response.ok) {
    const error = new Error(`Report request failed (${response.status}).`);
    error.status = response.status;
    throw error;
  }

  return response.json();
}