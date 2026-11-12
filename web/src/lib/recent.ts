// Recently checked values, per browser (convenience only: never relied upon).
const KEY = 'check:recent';
export interface RecentItem {
  value: string;
  path: string;
  label: string;
  at: number;
  count: number;
}

export function getRecent(): RecentItem[] {
  try {
    const raw = localStorage.getItem(KEY);
    const list = raw ? (JSON.parse(raw) as RecentItem[]) : [];
    return list.sort((a, b) => b.count * 0.2 + b.at / 3.6e6 - (a.count * 0.2 + a.at / 3.6e6)).slice(0, 20);
  } catch {
    return [];
  }
}

export function pushRecent(item: Omit<RecentItem, 'at' | 'count'>) {
  try {
    const list = getRecent().filter((r) => !(r.value === item.value && r.path === item.path));
    const prev = getRecent().find((r) => r.value === item.value && r.path === item.path);
    list.unshift({ ...item, at: Date.now(), count: (prev?.count ?? 0) + 1 });
    localStorage.setItem(KEY, JSON.stringify(list.slice(0, 40)));
  } catch {
    /* storage unavailable */
  }
}

export function clearRecent() {
  try {
    localStorage.removeItem(KEY);
  } catch {
    /* ignore */
  }
}
