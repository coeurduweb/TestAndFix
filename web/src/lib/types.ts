// Shapes returned by the server (mirror of server/src/knowledge/engine.ts and tools/types.ts).
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  id: string;
  family: string;
  severity: Severity;
  penalty: number;
  title: string;
  why: string;
  fix: string[];
  providerFix?: { provider: string; text: string };
  exampleBad?: string;
  exampleGood?: string;
  suggested?: string;
  references: string[];
  evidence?: string;
  fallback?: boolean;
  section?: string;
  /** mail reports only: what this finding does to delivery, and which side it is on */
  impact?: 'blocking' | 'spam' | 'advice';
  axis?: 'sender' | 'message';
}

export interface PassedCheck {
  id: string;
  family: string;
  title: string;
  detail?: string;
  section?: string;
}

export interface CheckResult<D = unknown> {
  tool: string;
  input: string;
  measuredAt: string;
  score?: number;
  findings: Finding[];
  passed: PassedCheck[];
  unavailable?: { source: string; reason: string }[];
  data: D;
  resultId?: string;
  ms?: number;
}
