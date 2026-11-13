// Detection of the sending provider (ESP, hosted mailbox, web host) from the signals a received
import { t } from '../i18n.js';
// message carries: DKIM d= domains, SPF includes of the sender's record, provider-specific
// headers, reverse DNS of the sending IP, HELO name and Message-ID domain.
// The key matches the `fix_by_provider` keys of knowledge/SCHEMA.md.

export interface ProviderSignals {
  /** d= domains of the DKIM signatures (any result). */
  dkimDomains?: string[];
  /** SPF record of the envelope or From domain. */
  spfRecord?: string;
  /** Lower-cased header names to values. */
  headers?: Map<string, string[]> | Record<string, string | string[]>;
  ptr?: string[];
  helo?: string;
  messageId?: string;
  returnPath?: string;
}

export interface ProviderInfo {
  key: string;
  name: string;
  /** SPF include the provider documents for a custom domain, when it has one. */
  spfInclude?: string;
  /** Official setup documentation (authentication of a custom domain). */
  docs?: string;
}

export interface DetectedProvider extends ProviderInfo {
  /** 0..1, grows with the number of independent signals. */
  confidence: number;
  evidence: string[];
}

interface Rule extends ProviderInfo {
  dkim?: RegExp;
  spf?: RegExp;
  /** header name (lower case) and optional value pattern */
  headers?: [string, RegExp?][];
  ptr?: RegExp;
  helo?: RegExp;
  messageId?: RegExp;
  returnPath?: RegExp;
}

// SPF includes are the ones the providers publish in their setup instructions for a custom domain.
// Documentation links are kept only for pages checked by hand.
export const PROVIDERS: Rule[] = [
  {
    key: 'google_workspace',
    name: 'Google Workspace',
    spfInclude: '_spf.google.com',
    docs: 'https://support.google.com/a/answer/10685031',
    dkim: /(^|\.)(google\.com|gmail\.com|googlemail\.com)$/,
    spf: /include:_spf\.google\.com/i,
    headers: [['x-gm-message-state'], ['x-google-smtp-source'], ['x-gm-gg'], ['x-google-dkim-signature']],
    ptr: /\.(google\.com|googlemail\.com)$/,
    helo: /\.(google\.com)$/,
  },
  {
    key: 'microsoft_365',
    name: 'Microsoft 365',
    spfInclude: 'spf.protection.outlook.com',
    docs: 'https://learn.microsoft.com/defender-office-365/email-authentication-spf-configure',
    dkim: /(^|\.)onmicrosoft\.com$/,
    spf: /include:spf\.protection\.outlook\.com/i,
    headers: [['x-ms-exchange-organization-authas'], ['x-ms-exchange-crosstenant-id'], ['x-ms-publictraffictype'], ['x-ms-traffictypediagnostic']],
    ptr: /\.(outbound\.protection\.outlook\.com|protection\.outlook\.com)$/,
    helo: /\.(outbound\.protection\.outlook\.com|prod\.outlook\.com)$/,
  },
  {
    key: 'brevo',
    name: 'Brevo',
    spfInclude: 'spf.brevo.com',
    dkim: /(^|\.)(sendinblue\.com|brevo\.com|sibforms\.com)$/,
    spf: /include:spf\.(brevo|sendinblue)\.com/i,
    headers: [['x-sib-id'], ['x-mailin-eid'], ['x-mailin-client'], ['x-brevo-campaign'], ['feedback-id', /sendinblue|brevo/i]],
    ptr: /\.(sendinblue\.com|brevo\.com|sendibm\d*\.com|sendibt\d*\.com)$/,
    returnPath: /@(.*\.)?(sendinblue\.com|brevo\.com|sendibm\d*\.com|sendibt\d*\.com)$/,
  },
  {
    key: 'mailchimp',
    name: 'Mailchimp / Mandrill',
    spfInclude: 'spf.mandrillapp.com',
    dkim: /(^|\.)(mcsv\.net|mcdlv\.net|mailchimpapp\.net|mandrillapp\.com|mcmail\.net)$/,
    spf: /include:(servers\.mcsv\.net|spf\.mandrillapp\.com)/i,
    headers: [['x-mc-user'], ['x-mandrill-user'], ['x-mailchimp-campaign'], ['list-id', /mcsv\.net/i], ['x-campaign', /mailchimp/i]],
    ptr: /\.(mcsv\.net|mcdlv\.net|rsgsv\.net|mandrillapp\.com)$/,
    returnPath: /@(.*\.)?(mcsv\.net|mcdlv\.net|rsgsv\.net|mandrillapp\.com)$/,
  },
  {
    key: 'mailjet',
    name: 'Mailjet',
    spfInclude: 'spf.mailjet.com',
    dkim: /(^|\.)mailjet\.com$/,
    spf: /include:spf\.mailjet\.com/i,
    headers: [['x-mj-mid'], ['x-mailjet-campaign'], ['x-mj-campaign'], ['x-csa-complaints', /mailjet/i]],
    ptr: /\.mailjet\.com$/,
    returnPath: /@(.*\.)?(mailjet\.com|bnc\d*\.mailjet\.com)$/,
  },
  {
    key: 'sendgrid',
    name: 'SendGrid',
    spfInclude: 'sendgrid.net',
    dkim: /(^|\.)sendgrid\.(net|info)$/,
    spf: /include:sendgrid\.net/i,
    headers: [['x-sg-eid'], ['x-sg-id'], ['x-entity-id']],
    ptr: /\.(sendgrid\.net|sendgrid\.info)$/,
    returnPath: /@(.*\.)?sendgrid\.net$/,
  },
  {
    key: 'mailgun',
    name: 'Mailgun',
    spfInclude: 'mailgun.org',
    dkim: /(^|\.)(mailgun\.org|mailgun\.net)$/,
    spf: /include:mailgun\.org/i,
    headers: [['x-mailgun-sid'], ['x-mailgun-tag'], ['x-mailgun-variables']],
    ptr: /\.(mailgun\.net|mailgun\.org)$/,
  },
  {
    key: 'amazon_ses',
    name: 'Amazon SES',
    spfInclude: 'amazonses.com',
    docs: 'https://docs.aws.amazon.com/ses/latest/dg/send-email-authentication-spf.html',
    dkim: /(^|\.)amazonses\.com$/,
    spf: /include:amazonses\.com/i,
    headers: [['x-ses-outgoing'], ['feedback-id', /amazonses/i]],
    ptr: /\.(amazonses\.com|smtp-out\.[a-z0-9-]+\.amazonses\.com)$/,
    messageId: /@([a-z0-9-]+\.)*amazonses\.com>?$/,
    returnPath: /@(.*\.)?amazonses\.com$/,
  },
  {
    key: 'postmark',
    name: 'Postmark',
    spfInclude: 'spf.mtasv.net',
    dkim: /(^|\.)(mtasv\.net|postmarkapp\.com|pm\.mtasv\.net)$/,
    spf: /include:spf\.mtasv\.net/i,
    headers: [['x-pm-message-id'], ['x-pm-tag'], ['x-pm-rcpt']],
    ptr: /\.mtasv\.net$/,
    returnPath: /@(.*\.)?(mtasv\.net|postmarkapp\.com)$/,
  },
  {
    key: 'sparkpost',
    name: 'SparkPost',
    spfInclude: 'sparkpostmail.com',
    dkim: /(^|\.)(sparkpostmail\.com|sparkpost\.com)$/,
    spf: /include:sparkpostmail\.com/i,
    headers: [['x-msfbl'], ['x-sparkpost-campaign']],
    ptr: /\.(sparkpostmail\.com|sparkpost\.com)$/,
    returnPath: /@(.*\.)?sparkpostmail\.com$/,
  },
  {
    key: 'hubspot',
    name: 'HubSpot',
    dkim: /(^|\.)(hubspotemail\.net|hubspot\.com|hs-email\.net)$/,
    spf: /hubspotemail\.net/i,
    headers: [['x-hs-cid'], ['x-hubspot-message-id'], ['x-report-abuse-to', /hubspot/i]],
    ptr: /\.(hubspotemail\.net|hubspot\.net)$/,
    returnPath: /@(.*\.)?(hubspotemail\.net|bf\d*\.hubspotemail\.net)$/,
  },
  {
    key: 'salesforce',
    name: 'Salesforce',
    spfInclude: '_spf.salesforce.com',
    dkim: /(^|\.)(salesforce\.com|exacttarget\.com|exct\.net|marketingcloudapis\.com)$/,
    spf: /include:(_spf\.salesforce\.com|cust-spf\.exacttarget\.com)/i,
    headers: [['x-sfdc-lk'], ['x-sfdc-user'], ['x-sfmc-stack'], ['x-sfdc-entityid']],
    ptr: /\.(salesforce\.com|exacttarget\.com|exct\.net)$/,
    returnPath: /@(.*\.)?(salesforce\.com|exacttarget\.com|exct\.net)$/,
  },
  {
    key: 'ovh',
    name: 'OVHcloud',
    spfInclude: 'mx.ovh.com',
    dkim: /(^|\.)ovh\.(net|com)$/,
    spf: /include:mx\.ovh\.com/i,
    headers: [['x-ovh-tracer-id'], ['x-ovh-remote']],
    ptr: /\.(ovh\.net|ovh\.com|mail\.ovh\.net)$/,
    helo: /\.(ovh\.net|mail\.ovh\.net)$/,
  },
  {
    key: 'o2switch',
    name: 'o2switch',
    ptr: /\.o2switch\.net$/,
    helo: /\.o2switch\.net$/,
    spf: /o2switch\.net/i,
    headers: [['x-o2switch-mailscanner']],
  },
  {
    key: 'infomaniak',
    name: 'Infomaniak',
    spfInclude: 'spf.infomaniak.ch',
    dkim: /(^|\.)infomaniak\.(ch|com)$/,
    spf: /include:spf\.infomaniak\.ch/i,
    headers: [['x-infomaniak-routing']],
    ptr: /\.infomaniak\.(ch|com)$/,
  },
  {
    key: 'zoho',
    name: 'Zoho Mail',
    spfInclude: 'zoho.com',
    dkim: /(^|\.)zoho(mail)?\.(com|eu|in)$/,
    spf: /include:zoho(mail)?\.(com|eu|in)/i,
    headers: [['x-zohomail-dkim'], ['x-zohomailclient'], ['x-zoho-virus-status']],
    ptr: /\.zoho(mail)?\.(com|eu|in)$/,
  },
  {
    key: 'proton',
    name: 'Proton Mail',
    spfInclude: '_spf.protonmail.ch',
    dkim: /(^|\.)(protonmail\.ch|proton\.me|protonmail\.com)$/,
    spf: /include:_spf\.protonmail\.ch/i,
    headers: [['x-pm-origin'], ['x-pm-content-encryption']],
    ptr: /\.(protonmail\.ch|proton\.ch)$/,
  },
  {
    key: 'gandi',
    name: 'Gandi',
    spfInclude: '_mailcust.gandi.net',
    dkim: /(^|\.)gandi\.net$/,
    spf: /include:_mailcust\.gandi\.net/i,
    ptr: /\.gandi\.net$/,
  },
  {
    key: 'ionos',
    name: 'IONOS',
    spfInclude: '_spf-eu.ionos.com',
    dkim: /(^|\.)(ionos\.(com|fr|de)|kundenserver\.de|1and1\.(com|fr))$/,
    spf: /include:_spf(-eu|-us)?\.ionos\.com/i,
    headers: [['x-provags-id'], ['x-ui-out-filterresults']],
    ptr: /\.(kundenserver\.de|ionos\.(com|fr|de)|perfora\.net|1and1\.(com|fr))$/,
  },
  {
    key: 'cpanel',
    name: 'cPanel',
    headers: [['x-authenticated-sender'], ['x-get-message-sender-via'], ['x-antiabuse']],
  },
  {
    key: 'plesk',
    name: 'Plesk',
    headers: [['x-ppp-message-id'], ['x-ppp-vhost']],
  },
  {
    key: 'wordpress',
    name: 'WordPress',
    headers: [['x-mailer', /wordpress|wpmail|wp mail smtp|phpmailer.*wordpress/i]],
  },
];

const BY_KEY = new Map(PROVIDERS.map((p) => [p.key, p]));

export function providerInfo(key: string | undefined): ProviderInfo | undefined {
  const p = key ? BY_KEY.get(key) : undefined;
  return p ? { key: p.key, name: p.name, spfInclude: p.spfInclude, docs: p.docs } : undefined;
}

function headerValues(h: ProviderSignals['headers'], name: string): string[] {
  if (!h) return [];
  if (h instanceof Map) return h.get(name) ?? [];
  const v = (h as Record<string, string | string[]>)[name];
  return v === undefined ? [] : Array.isArray(v) ? v : [v];
}

const norm = (s: string) => s.trim().toLowerCase().replace(/\.$/, '');

/**
 * Score every provider against the signals and return them by decreasing confidence.
 * Hosting control panels (cPanel, Plesk) and WordPress only come out when nothing more
 * specific matched, as they usually sit behind one of the others.
 */
export function detectProviders(s: ProviderSignals): DetectedProvider[] {
  const out: DetectedProvider[] = [];
  const dkim = (s.dkimDomains ?? []).map(norm);
  const ptr = (s.ptr ?? []).map(norm);
  const helo = s.helo ? norm(s.helo) : '';
  for (const p of PROVIDERS) {
    const evidence: string[] = [];
    let weight = 0;
    if (p.dkim) {
      const d = dkim.find((x) => p.dkim!.test(x));
      if (d) {
        evidence.push(`signature DKIM d=${d}`);
        weight += 0.5;
      }
    }
    if (p.spf && s.spfRecord && p.spf.test(s.spfRecord)) {
      evidence.push(`SPF : ${(s.spfRecord.match(p.spf) ?? [''])[0]}`);
      weight += 0.2;
    }
    for (const [name, re] of p.headers ?? []) {
      const vals = headerValues(s.headers, name);
      const hit = vals.find((v) => (re ? re.test(v) : true));
      if (hit !== undefined) {
        evidence.push(t('en-tête {name}', { name }));
        weight += 0.35;
        break;
      }
    }
    if (p.ptr) {
      const hit = ptr.find((x) => p.ptr!.test(x));
      if (hit) {
        evidence.push(`reverse DNS ${hit}`);
        weight += 0.45;
      }
    }
    if (p.helo && helo && p.helo.test(helo)) {
      evidence.push(`HELO ${helo}`);
      weight += 0.25;
    }
    if (p.messageId && s.messageId && p.messageId.test(norm(s.messageId))) {
      evidence.push('Message-ID');
      weight += 0.2;
    }
    if (p.returnPath && s.returnPath && p.returnPath.test(norm(s.returnPath))) {
      evidence.push(`Return-Path ${norm(s.returnPath)}`);
      weight += 0.3;
    }
    if (weight > 0) {
      out.push({
        key: p.key,
        name: p.name,
        spfInclude: p.spfInclude,
        docs: p.docs,
        confidence: Math.min(1, Math.round(weight * 100) / 100),
        evidence,
      });
    }
  }
  const generic = new Set(['cpanel', 'plesk', 'wordpress']);
  // An SPF include says the domain MAY send through a service, not that this message did: a candidate
  // seen only there comes after any seen in the message itself (2026-11-13: a message sent by a cPanel
  // server was labelled "Google Workspace (probable)" from include:_spf.google.com alone).
  const spfOnly = (d: DetectedProvider) => d.evidence.every((e) => e.startsWith('SPF : '));
  return out.sort((a, b) => Number(spfOnly(a)) - Number(spfOnly(b)) || Number(generic.has(a.key)) - Number(generic.has(b.key)) || b.confidence - a.confidence);
}

/** The most likely provider, or undefined when no signal matched. */
export function detectProvider(s: ProviderSignals): DetectedProvider | undefined {
  return detectProviders(s)[0];
}
