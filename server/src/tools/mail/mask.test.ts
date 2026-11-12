import { describe, expect, it } from 'vitest';
import { maskRaw } from './index.js';

const id = 't-7k2m9q4x';
const raw = (body: string, cte: string) =>
  Buffer.from(
    [
      `To: ${id}@test.example`,
      'From: a@b.example',
      'Subject: x',
      'MIME-Version: 1.0',
      'Content-Type: multipart/alternative; boundary="b1"',
      '',
      '--b1',
      'Content-Type: text/plain; charset=utf-8',
      `Content-Transfer-Encoding: ${cte}`,
      '',
      body,
      '--b1--',
      '',
    ].join('\r\n'),
    'latin1',
  );

describe('masking the test address in a shared raw source', () => {
  it('masks it in plain text, in base64 and across quoted-printable soft breaks', () => {
    const plain = maskRaw(raw(`sent to ${id}@test.example`, '7bit'), id).toString('latin1');
    expect(plain).not.toMatch(/t-7k2m9q4x/i);
    const b64 = maskRaw(raw(Buffer.from(`This message was sent to ${id}@test.example, thanks.`).toString('base64'), 'base64'), id).toString('latin1');
    const decoded = Buffer.from(b64.split('\r\n\r\n')[2].split('\r\n--b1')[0].replace(/\r\n/g, ''), 'base64').toString();
    expect(decoded).toBe('This message was sent to t-00000000@test.example, thanks.');
    const qp = maskRaw(raw(`sent to t-7k2m=\r\n9q4x@test.example`, 'quoted-printable'), id).toString('latin1');
    expect(qp.replace(/=\r\n/g, '')).not.toMatch(/t-7k2m9q4x/i);
    expect(qp).toContain('t-00000000@test.example');
  });
});
