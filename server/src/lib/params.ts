// Query-string numbers, read once and bounded (code review of 2026-11-12: Number('abc') gave NaN, a
// 500 from SQLite, and a negative limit became SQLite's LIMIT -1, no limit at all).
export function intParam(value: unknown, fallback: number, min: number, max: number): number {
  const n = typeof value === 'string' && /^-?\d+$/.test(value.trim()) ? Number(value) : typeof value === 'number' ? value : NaN;
  return Number.isFinite(n) ? Math.min(max, Math.max(min, Math.trunc(n))) : fallback;
}

/** A LIKE pattern matching `text` literally, for `LIKE ? ESCAPE '\\'`. */
export const likeContains = (text: string) => `%${text.replace(/[\\%_]/g, (c) => '\\' + c)}%`;
