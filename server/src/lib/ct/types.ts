// Shapes shared by the Certificate Transparency clients (crt.name, crt.sh, Cert Spotter).

/** One certificate seen in a CT search, reduced to what the subdomain inventory needs. */
export interface CtCert {
  source: CtSourceId;
  /** Stable id within the source (crt.sh id, Cert Spotter issuance id). */
  id: string;
  /** Hex serial number when the source gives it (crt.sh does, Cert Spotter does not). */
  serial?: string;
  /** Issuer distinguished name, e.g. "C=US, O=Let's Encrypt, CN=R10". */
  issuer: string;
  /** Short issuer name for display (organisation of the issuer, or Cert Spotter friendly_name). */
  issuerShort: string;
  /** ISO dates (UTC). */
  notBefore: string;
  notAfter: string;
  /** Every DNS name the certificate covers (lower case, wildcards kept as "*.x"). */
  names: string[];
  /** SHA-256 of the certificate, when known (Cert Spotter). */
  sha256?: string;
  revoked?: boolean;
}

/** A name from an index that keeps no certificate metadata (crt.name). */
export interface CtName {
  name: string;
  firstSeen?: string;
}

export type CtSourceId = 'crt.name' | 'crt.sh' | 'certspotter';

export const SOURCE_LABEL: Record<CtSourceId, string> = {
  'crt.name': 'crt.name',
  'crt.sh': 'crt.sh',
  certspotter: 'Cert Spotter',
};

export interface CtSourceResult {
  source: CtSourceId;
  status: 'ok' | 'error' | 'skipped';
  certs: CtCert[];
  names: CtName[];
  /** Why the source gave nothing (timeout, quota, HTTP status...), in French. */
  error?: string;
  /** The answer was cut at the size limit; what could be read was kept. */
  truncated?: boolean;
  /** Pages read (Cert Spotter), for the record. */
  pages?: number;
  ms: number;
}

/** Response of one HTTP GET made by a CT client. */
export interface CtResponse {
  status: number;
  headers: Record<string, string>;
  body: Buffer;
  truncated: boolean;
}

/** HTTP GET used by the clients: injected, so that tests never call the real services. */
export type CtFetch = (url: string, opts: { timeoutMs: number; maxBytes: number; signal?: AbortSignal }) => Promise<CtResponse>;
