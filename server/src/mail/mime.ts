// Raw message structure: header fields as written (unfolded, with their raw form), MIME tree with
// transfer encodings and charsets decoded. Kept separate from mailparser because the analysis
// needs what mailparser smooths over (a text part generated from HTML, folding, 8-bit bytes).

export interface RawHeader {
  name: string;
  /** lower-cased name */
  key: string;
  /** unfolded value, raw (encoded words not decoded) */
  value: string;
  /** field as written, with folding */
  raw: string;
}

export interface MimePart {
  path: string;
  headers: RawHeader[];
  contentType: string;
  params: Record<string, string>;
  cte: string;
  disposition?: string;
  filename?: string;
  contentId?: string;
  /** body bytes as transmitted */
  body: Buffer;
  /** body after transfer decoding (leaves only) */
  decoded: Buffer;
  /** decoded text for text/* parts */
  text?: string;
  /** charset used to decode text, and whether it was declared */
  charset?: string;
  charsetDeclared?: boolean;
  /** the declared charset is UTF-8 but the bytes are not valid UTF-8 */
  invalidUtf8?: boolean;
  has8bit: boolean;
  children: MimePart[];
}

export interface ParsedRaw {
  headers: RawHeader[];
  headerBytes: number;
  body: Buffer;
  root: MimePart;
  /** longest line of the whole message, CRLF excluded */
  maxLineLength: number;
  longLines: number;
}

export function splitHeaderBody(buf: Buffer): { head: string; body: Buffer; headerBytes: number } {
  // header ends at the first empty line (CRLF CRLF or LF LF)
  let idx = -1;
  let sepLen = 0;
  for (let i = 0; i < buf.length - 1; i++) {
    if (buf[i] === 0x0a && buf[i + 1] === 0x0a) {
      idx = i;
      sepLen = 2;
      break;
    }
    if (buf[i] === 0x0a && buf[i + 1] === 0x0d && buf[i + 2] === 0x0a) {
      idx = i;
      sepLen = 3;
      break;
    }
  }
  if (idx === -1) return { head: buf.toString('latin1'), body: Buffer.alloc(0), headerBytes: buf.length };
  return { head: buf.subarray(0, idx + 1).toString('latin1'), body: buf.subarray(idx + sepLen), headerBytes: idx + 1 };
}

/** Header block (latin1 string, so 8-bit bytes survive) to fields. */
export function parseHeaderBlock(head: string): RawHeader[] {
  const out: RawHeader[] = [];
  const lines = head.split(/\r?\n/);
  let cur: string[] | undefined;
  const flush = () => {
    if (!cur) return;
    const raw = cur.join('\r\n');
    const i = raw.indexOf(':');
    if (i > 0) {
      const name = raw.slice(0, i).trim();
      out.push({ name, key: name.toLowerCase(), value: raw.slice(i + 1).replace(/\r\n[ \t]+/g, ' ').trim(), raw });
    }
    cur = undefined;
  };
  for (const line of lines) {
    if (/^[ \t]/.test(line) && cur) cur.push(line);
    else {
      flush();
      if (line.length) cur = [line];
    }
  }
  flush();
  return out;
}

/** Parameters of a structured header (Content-Type, Content-Disposition), RFC 2231 included. */
export function parseParams(value: string): { main: string; params: Record<string, string> } {
  const parts: string[] = [];
  let cur = '';
  let q = false;
  for (const ch of value) {
    if (ch === '"') q = !q;
    if (ch === ';' && !q) {
      parts.push(cur);
      cur = '';
    } else cur += ch;
  }
  parts.push(cur);
  const main = (parts.shift() ?? '').trim().toLowerCase();
  const params: Record<string, string> = {};
  const continued: Record<string, { i: number; v: string; enc: boolean }[]> = {};
  for (const p of parts) {
    const eq = p.indexOf('=');
    if (eq < 0) continue;
    let k = p.slice(0, eq).trim().toLowerCase();
    let v = p.slice(eq + 1).trim();
    if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1).replace(/\\(.)/g, '$1');
    const m = /^([^*]+)\*(\d+)?(\*)?$/.exec(k);
    if (m) {
      k = m[1];
      (continued[k] ??= []).push({ i: Number(m[2] ?? 0), v, enc: !!m[3] || (m[2] === undefined && p.slice(0, eq).trim().endsWith('*')) });
      continue;
    }
    params[k] = v;
  }
  for (const [k, segs] of Object.entries(continued)) {
    segs.sort((a, b) => a.i - b.i);
    let charset = 'utf-8';
    const bytes: number[] = [];
    segs.forEach((s, n) => {
      let v = s.v;
      if (s.enc) {
        if (n === 0) {
          const mm = /^([^']*)'[^']*'(.*)$/.exec(v);
          if (mm) {
            charset = mm[1] || 'utf-8';
            v = mm[2];
          }
        }
        for (let i = 0; i < v.length; i++) {
          if (v[i] === '%' && /^[0-9a-f]{2}$/i.test(v.slice(i + 1, i + 3))) {
            bytes.push(parseInt(v.slice(i + 1, i + 3), 16));
            i += 2;
          } else bytes.push(v.charCodeAt(i) & 0xff);
        }
      } else for (const c of Buffer.from(v, 'latin1')) bytes.push(c);
    });
    params[k] = decodeCharset(Buffer.from(bytes), charset);
  }
  return { main, params };
}

export function decodeCharset(buf: Buffer, charset: string | undefined): string {
  const cs = (charset || 'utf-8').trim().toLowerCase().replace(/^"|"$/g, '');
  try {
    return new TextDecoder(cs === 'us-ascii' || cs === 'ascii' ? 'utf-8' : cs).decode(buf);
  } catch {
    return buf.toString('latin1');
  }
}

export function isValidUtf8(buf: Buffer): boolean {
  try {
    new TextDecoder('utf-8', { fatal: true }).decode(buf);
    return true;
  } catch {
    return false;
  }
}

export function decodeQuotedPrintable(input: Buffer): Buffer {
  const s = input.toString('latin1').replace(/=\r?\n/g, '');
  const out: number[] = [];
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '=' && /^[0-9A-Fa-f]{2}$/.test(s.slice(i + 1, i + 3))) {
      out.push(parseInt(s.slice(i + 1, i + 3), 16));
      i += 2;
    } else out.push(s.charCodeAt(i) & 0xff);
  }
  return Buffer.from(out);
}

/** RFC 2047 encoded words. Returns the decoded text and whether an encoded word was invalid. */
export function decodeWords(value: string): { text: string; invalid: boolean } {
  let invalid = false;
  const text = value
    .replace(/(=\?[^?]+\?[BbQq]\?[^?]*\?=)\s+(?==\?)/g, '$1')
    .replace(/=\?([^?*]+)(?:\*[^?]*)?\?([BbQq])\?([^?]*)\?=/g, (_m, cs: string, enc: string, data: string) => {
      try {
        const bytes =
          enc.toUpperCase() === 'B'
            ? Buffer.from(data, 'base64')
            : decodeQuotedPrintable(Buffer.from(data.replace(/_/g, ' '), 'latin1'));
        if (cs.toLowerCase() === 'utf-8' && !isValidUtf8(bytes)) invalid = true;
        return decodeCharset(bytes, cs);
      } catch {
        invalid = true;
        return data;
      }
    });
  return { text, invalid };
}

function has8bit(buf: Buffer): boolean {
  for (const b of buf) if (b > 0x7f) return true;
  return false;
}

function decodeBody(body: Buffer, cte: string): Buffer {
  if (cte === 'base64') return Buffer.from(body.toString('latin1').replace(/[^A-Za-z0-9+/=]/g, ''), 'base64');
  if (cte === 'quoted-printable') return decodeQuotedPrintable(body);
  return body;
}

function splitMultipart(body: Buffer, boundary: string): Buffer[] {
  const s = body.toString('latin1');
  const delim = '--' + boundary;
  const parts: Buffer[] = [];
  const re = new RegExp(`(^|\\r?\\n)${delim.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(--)?[ \\t]*(?=\\r?\\n|$)`, 'g');
  const marks: { start: number; end: number; close: boolean }[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(s))) marks.push({ start: m.index, end: m.index + m[0].length, close: !!m[2] });
  for (let i = 0; i < marks.length - 1; i++) {
    if (marks[i].close) break;
    let from = marks[i].end;
    if (s[from] === '\r') from++;
    if (s[from] === '\n') from++;
    parts.push(Buffer.from(s.slice(from, marks[i + 1].start), 'latin1'));
  }
  return parts;
}

export function parseMimePart(head: RawHeader[], body: Buffer, path = '1', depth = 0): MimePart {
  const ctH = head.find((h) => h.key === 'content-type')?.value;
  const { main, params } = parseParams(ctH ?? 'text/plain');
  const contentType = main.includes('/') ? main : 'text/plain';
  const cte = (head.find((h) => h.key === 'content-transfer-encoding')?.value ?? '7bit').toLowerCase().trim();
  const dispH = head.find((h) => h.key === 'content-disposition')?.value;
  const disp = dispH ? parseParams(dispH) : undefined;
  const rawName = disp?.params.filename ?? params.name;
  const part: MimePart = {
    path,
    headers: head,
    contentType,
    params,
    cte,
    disposition: disp?.main,
    filename: rawName ? decodeWords(rawName).text : undefined,
    contentId: head.find((h) => h.key === 'content-id')?.value.replace(/^<|>$/g, ''),
    body,
    decoded: Buffer.alloc(0),
    has8bit: has8bit(body),
    children: [],
  };
  if (contentType.startsWith('multipart/') && params.boundary && depth < 20) {
    splitMultipart(body, params.boundary).forEach((chunk, i) => {
      const { head: h, body: b } = splitHeaderBody(chunk);
      // a part may start directly with an empty line (no headers)
      const headers = /^\r?\n/.test(chunk.toString('latin1', 0, 2)) ? [] : parseHeaderBlock(h);
      const bodyBuf = headers.length ? b : chunk.subarray(/^\r\n/.test(chunk.toString('latin1', 0, 2)) ? 2 : 1);
      part.children.push(parseMimePart(headers, bodyBuf, `${path}.${i + 1}`, depth + 1));
    });
    return part;
  }
  if (contentType === 'message/rfc822' && depth < 20) {
    part.decoded = decodeBody(body, cte);
    return part;
  }
  part.decoded = decodeBody(body, cte);
  if (contentType.startsWith('text/')) {
    part.charsetDeclared = !!params.charset;
    part.charset = params.charset?.toLowerCase();
    part.text = decodeCharset(part.decoded, part.charset);
    if ((part.charset ?? 'utf-8') === 'utf-8' && has8bit(part.decoded) && !isValidUtf8(part.decoded)) part.invalidUtf8 = true;
  }
  return part;
}

export function parseRaw(raw: Buffer): ParsedRaw {
  const { head, body, headerBytes } = splitHeaderBody(raw);
  const headers = parseHeaderBlock(head);
  let maxLineLength = 0;
  let longLines = 0;
  let start = 0;
  for (let i = 0; i <= raw.length; i++) {
    if (i === raw.length || raw[i] === 0x0a) {
      let len = i - start;
      if (len > 0 && raw[i - 1] === 0x0d) len--;
      if (len > maxLineLength) maxLineLength = len;
      if (len > 998) longLines++;
      start = i + 1;
    }
  }
  return { headers, headerBytes, body, root: parseMimePart(headers, body), maxLineLength, longLines };
}

export function walk(part: MimePart, fn: (p: MimePart) => void) {
  fn(part);
  for (const c of part.children) walk(c, fn);
}

export function leaves(part: MimePart): MimePart[] {
  const out: MimePart[] = [];
  walk(part, (p) => {
    if (!p.children.length && !p.contentType.startsWith('multipart/')) out.push(p);
  });
  return out;
}

/** Text and HTML bodies (first of each that is not an attachment) and attachments. */
export function bodyParts(root: MimePart): { text?: MimePart; html?: MimePart; attachments: MimePart[]; inline: MimePart[] } {
  let text: MimePart | undefined;
  let html: MimePart | undefined;
  const attachments: MimePart[] = [];
  const inline: MimePart[] = [];
  for (const p of leaves(root)) {
    const isAttachment = p.disposition === 'attachment' || (!!p.filename && !p.contentType.startsWith('text/plain') && !p.contentType.startsWith('text/html'));
    if (!isAttachment && p.contentType === 'text/plain' && !text) text = p;
    else if (!isAttachment && p.contentType === 'text/html' && !html) html = p;
    else if (p.disposition === 'inline' && p.contentId && p.contentType.startsWith('image/')) inline.push(p);
    else if (isAttachment || p.contentType === 'message/rfc822' || !p.contentType.startsWith('text/')) {
      if (p.contentId && !p.filename && p.contentType.startsWith('image/')) inline.push(p);
      else attachments.push(p);
    }
  }
  return { text, html, attachments, inline };
}

export function headerValues(headers: RawHeader[], key: string): string[] {
  return headers.filter((h) => h.key === key).map((h) => h.value);
}

export function firstHeader(headers: RawHeader[], key: string): string | undefined {
  return headers.find((h) => h.key === key)?.value;
}
