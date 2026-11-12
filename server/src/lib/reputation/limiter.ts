// Local request queue for APIs with a hard per-minute quota (VirusTotal free key: 4 per minute,
// 500 per day, https://docs.virustotal.com/reference/public-vs-premium-api). Requests wait their
// turn in order; a request that would wait longer than its caller allows is turned down with the
// time to wait, so the result says "quota" instead of hanging. Counters live in memory only: a
// restart forgets them, and the API's own 429 is still handled by the client.
import { SourceUnavailable } from './source.js';
import { t } from '../../i18n.js';

export class RateLimiter {
  private stamps: number[] = [];
  private day = '';
  private dayCount = 0;
  private chain: Promise<void> = Promise.resolve();

  constructor(
    public readonly perMinute: number,
    public readonly perDay: number,
    private label: string,
    private now: () => number = () => Date.now(),
    private sleep: (ms: number) => Promise<void> = (ms) => new Promise((r) => setTimeout(r, ms)),
  ) {}

  /** Wait for a slot, first come first served. Rejects with SourceUnavailable('quota'). */
  acquire(maxWaitMs: number): Promise<void> {
    const deadline = this.now() + maxWaitMs;
    const run = this.chain.then(() => this.take(deadline));
    this.chain = run.catch(() => undefined);
    return run;
  }

  /** The API said 429: consider the current minute spent. */
  saturate() {
    const t = this.now();
    while (this.stamps.length < this.perMinute) this.stamps.push(t);
  }

  get usedToday(): number {
    return this.day === this.dayKey(this.now()) ? this.dayCount : 0;
  }

  private dayKey(t: number) {
    return new Date(t).toISOString().slice(0, 10);
  }

  private async take(deadline: number): Promise<void> {
    let now = this.now();
    const key = this.dayKey(now);
    if (key !== this.day) {
      this.day = key;
      this.dayCount = 0;
    }
    if (this.dayCount >= this.perDay)
      throw new SourceUnavailable('quota', t('quota quotidien de {label} atteint ({perDay} requêtes par jour), réessayez demain', { label: this.label, perDay: this.perDay }));
    this.stamps = this.stamps.filter((s) => s > now - 60000);
    if (this.stamps.length >= this.perMinute) {
      const wait = this.stamps[0] + 60000 - now;
      if (now + wait > deadline)
        throw new SourceUnavailable(
          'quota',
          t('quota de {label} atteint ({perMinute} requêtes par minute) : réessayez dans {s} s', { label: this.label, perMinute: this.perMinute, s: Math.ceil(wait / 1000) }),
        );
      await this.sleep(wait);
      now = this.now();
      this.stamps = this.stamps.filter((s) => s > now - 60000);
    }
    this.stamps.push(now);
    this.dayCount++;
  }
}
