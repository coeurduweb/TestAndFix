// Files dropped anywhere in the app, handed to the page that takes them.
let files: File[] = [];
export function setPendingFiles(f: File[]) {
  files = f;
}
export function takePendingFiles(): File[] {
  const f = files;
  files = [];
  return f;
}
export function takePendingText(key: string): string | null {
  try {
    const v = sessionStorage.getItem(key);
    if (v !== null) sessionStorage.removeItem(key);
    return v;
  } catch {
    return null;
  }
}
