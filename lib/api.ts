'use client';

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:5000';

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export async function apiRequest<T>(path: string, token: string | null, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  headers.set('Content-Type', 'application/json');
  if (token) headers.set('Authorization', `Bearer ${token}`);

  try {
    const response = await fetch(`${API_URL}${path}`, { ...init, headers, cache: 'no-store' });
    if (response.status === 401) throw new ApiError(401, 'Unauthorized');
    if (!response.ok) throw new ApiError(response.status, await response.text());
    return response.json() as Promise<T>;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(0, 'Backend disconnected');
  }
}
