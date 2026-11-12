import { describe, expect, it } from 'vitest';
import { SseParser, type SseEvent } from './sse';

function parse(chunks: string[]): SseEvent[] {
  const out: SseEvent[] = [];
  const p = new SseParser((e) => out.push(e));
  for (const c of chunks) p.push(c);
  p.end();
  return out;
}

describe('SseParser', () => {
  it('reads named events with JSON data', () => {
    expect(parse(['event: start\ndata: {"ip":"8.8.8.8"}\n\n'])).toEqual([{ type: 'start', data: { ip: '8.8.8.8' } }]);
  });

  it('defaults to "message" and keeps raw text that is not JSON', () => {
    expect(parse(['data: bonjour\n\n'])).toEqual([{ type: 'message', data: 'bonjour' }]);
  });

  it('ignores comments (heartbeats) and events without data', () => {
    expect(parse([': ok\n\n', ': ping\n\nevent: lone\n\n', 'event: row\ndata: 1\n\n'])).toEqual([{ type: 'row', data: 1 }]);
  });

  it('joins several data lines with a newline', () => {
    expect(parse(['data: a\ndata: b\n\n'])).toEqual([{ type: 'message', data: 'a\nb' }]);
  });

  it('survives chunks cut anywhere, even inside the field name', () => {
    const text = 'event: row\ndata: {"ip":"1.1.1.1","n":1}\n\nevent: done\ndata: {"ok":true}\n\n';
    for (let cut = 1; cut < text.length; cut++) {
      expect(parse([text.slice(0, cut), text.slice(cut)])).toEqual([
        { type: 'row', data: { ip: '1.1.1.1', n: 1 } },
        { type: 'done', data: { ok: true } },
      ]);
    }
  });

  it('accepts CRLF and lone CR line ends, CRLF split across chunks included', () => {
    expect(parse(['event: a\r\ndata: 1\r', '\n\r\nevent: b\rdata: 2\r\r'])).toEqual([
      { type: 'a', data: 1 },
      { type: 'b', data: 2 },
    ]);
  });

  it('strips only one space after the colon, and takes a line without colon as a field with an empty value (WHATWG)', () => {
    expect(parse(['data:  x\n\n'])).toEqual([{ type: 'message', data: ' x' }]);
    expect(parse(['data\n\n'])).toEqual([{ type: 'message', data: '' }]);
  });

  it('drops a last event without its blank line', () => {
    expect(parse(['event: row\ndata: 1\n\nevent: row\ndata: 2'])).toEqual([{ type: 'row', data: 1 }]);
  });

  it('keeps one byte stream decoded as UTF-8 across chunks (TextDecoderStream upstream)', () => {
    const bytes = new TextEncoder().encode('data: "Réputation d’IP"\n\n');
    const dec = new TextDecoder();
    const out: SseEvent[] = [];
    const p = new SseParser((e) => out.push(e));
    for (let i = 0; i < bytes.length; i += 3) p.push(dec.decode(bytes.slice(i, i + 3), { stream: true }));
    expect(out).toEqual([{ type: 'message', data: 'Réputation d’IP' }]);
  });
});
