import type { FastifyInstance } from 'fastify';
import type { DB } from '../db.js';
import type { Config } from '../config.js';
import type { ResolveSession, SessionOptions } from '../dns/iterative.js';

export interface ToolContext {
  db: DB;
  config: Config;
  /** A fresh iterative resolution session, to be used for ONE user action and dropped. */
  dns(opts?: SessionOptions): ResolveSession;
}

export interface ServerTool {
  id: string;
  /** Routes that need the password (most tools). */
  register?(app: FastifyInstance, ctx: ToolContext): void | Promise<void>;
  /** Routes open without password (generators). */
  registerPublic?(app: FastifyInstance, ctx: ToolContext): void | Promise<void>;
  /** Background work started with the server (SMTP listener, daily qualification…). */
  start?(ctx: ToolContext): void | Promise<void>;
  stop?(): void | Promise<void>;
}

import type { Finding } from '../knowledge/engine.js';

/** A check that passed, shown in the "Contrôles réussis" list. */
export interface PassedCheck {
  id: string;
  family: string;
  title: string;
  detail?: string;
}

/** Common envelope returned by every checking tool. */
export interface CheckResult<D = unknown> {
  tool: string;
  input: string;
  /** ISO timestamp of the measurement (to the second). */
  measuredAt: string;
  /** /10, when the tool grades. */
  score?: number;
  findings: Finding[];
  passed: PassedCheck[];
  /** Sources that could not be queried (missing key, timeout): shown, never blocking. */
  unavailable?: { source: string; reason: string }[];
  /** Tool-specific payload. */
  data: D;
  /** History id, to build a stable link. */
  resultId?: string;
  ms?: number;
}
