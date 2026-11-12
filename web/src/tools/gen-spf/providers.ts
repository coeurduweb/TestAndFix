// Sending services the SPF generator knows. The include values are the official ones recorded in
// knowledge/situations/spf.yaml (fix_by_provider, read on the providers' documentation on
// 2026-11-10); nothing here is guessed. The lookup cost of each include was measured on
// 2026-11-10 with check's own SPF analysis (1 for the include itself + the lookups of its target):
// it changes when a provider rewrites its record, hence "measured on" next to every figure.

import { msg } from '../../lib/i18n';

export const COSTS_MEASURED_ON = '2026-11-10';

export interface SpfProvider {
  key: string;
  name: string;
  /** Official include value, without "include:". */
  include?: string;
  /** DNS lookups of `include:<include>` measured on COSTS_MEASURED_ON. */
  cost?: number;
  /** Where the include belongs when it is not the root SPF of the domain. */
  elsewhere?: string;
  /** Short note shown when the service is selected. */
  note?: string;
  /** Extra include, optional (Gandi web hosting). */
  extra?: { include: string; cost: number; label: string };
  /** The include is specific to the account and must be typed. */
  accountInclude?: { placeholder: string; pattern: RegExp; hint: string };
  /** Other include values meaning the same provider (old names). */
  aliases?: string[];
  /** MX host names that reveal the provider hosts the mailboxes. */
  mx?: RegExp;
  /** Words matched by the search box. */
  keywords: string;
  /** Documentation cited in the knowledge base. */
  docs?: string;
}

export const SPF_PROVIDERS: SpfProvider[] = [
  {
    key: 'google_workspace', name: 'Google Workspace', include: '_spf.google.com', cost: 1,
    mx: /(^|\.)(google|googlemail)\.com$/, keywords: 'google workspace gmail gsuite g suite',
    docs: 'https://knowledge.workspace.google.com/admin/security/set-up-spf',
  },
  {
    key: 'microsoft_365', name: 'Microsoft 365', include: 'spf.protection.outlook.com', cost: 1,
    mx: /\.mail\.protection\.outlook\.com$/, keywords: 'microsoft 365 office outlook exchange online o365',
    docs: 'https://learn.microsoft.com/en-us/defender-office-365/email-authentication-spf-configure',
  },
  {
    key: 'brevo', name: 'Brevo', include: 'spf.brevo.com', cost: 1, aliases: ['spf.sendinblue.com'],
    note: msg("Brevo n'exige pas de SPF pour authentifier un domaine ; l'include sert si vous fusionnez son envoi dans votre SPF."),
    keywords: 'brevo sendinblue newsletter emailing', docs: 'https://help.brevo.com/hc/en-us/articles/4414335084434-Merge-multiple-SPF-records',
  },
  {
    key: 'mailchimp', name: 'Mailchimp',
    elsewhere: msg("Rien à ajouter : Mailchimp envoie avec son propre domaine de retour, déjà couvert par son SPF. Authentifiez plutôt le domaine en DKIM (Account & billing, Domains)."),
    keywords: 'mailchimp mandrill intuit newsletter emailing',
  },
  {
    key: 'mailjet', name: 'Mailjet', include: 'spf.mailjet.com', cost: 1, keywords: 'mailjet sinch newsletter emailing',
    docs: 'https://documentation.mailjet.com/hc/en-us/articles/360049641733-Authenticating-Domains-with-SPF-and-DKIM-A-Complete-Guide',
  },
  {
    key: 'sendgrid', name: 'SendGrid', include: 'sendgrid.net', cost: 2,
    elsewhere: msg("Avec l'option automated security (par défaut), l'include sendgrid.net est porté par le sous-domaine em… que SendGrid vous fait déléguer en CNAME : publiez les CNAME de Settings, Sender Authentication. Sans cette option, l'include va sur ce sous-domaine."),
    keywords: 'sendgrid twilio transactionnel', docs: 'https://www.twilio.com/docs/sendgrid/ui/account-and-settings/how-to-set-up-domain-authentication',
  },
  {
    key: 'amazon_ses', name: 'Amazon SES', include: 'amazonses.com', cost: 1,
    elsewhere: msg("Par défaut SES utilise un domaine de retour amazonses.com, déjà couvert. Pour un domaine de retour personnalisé (MAIL FROM), publiez sur ce sous-domaine un MX 10 feedback-smtp.<région>.amazonses.com et le TXT v=spf1 include:amazonses.com ~all."),
    keywords: 'amazon ses aws simple email service', docs: 'https://docs.aws.amazon.com/ses/latest/dg/mail-from.html',
  },
  {
    key: 'ovh', name: 'OVHcloud', include: 'mx.ovh.com', cost: 3, mx: /(^|\.)ovh\.(net|ca)$/,
    note: msg('Valable pour MX Plan, Email Pro et Exchange hébergé. Comptes Canada et Asie-Pacifique : include:mx.ovh.ca (3 requêtes aussi).'),
    keywords: 'ovh ovhcloud mx plan email pro exchange', docs: 'https://docs.ovhcloud.com/fr/guides/web-cloud/domains/dns-zone-spf',
  },
  {
    key: 'o2switch', name: 'o2switch', include: 'spf.jabatus.fr', cost: 1,
    note: msg("o2switch indique que le seul include à utiliser pour ses services est include:spf.jabatus.fr (cPanel, Authentification, Gérer, Personnaliser)."),
    keywords: 'o2switch cpanel jabatus hebergement', docs: 'https://faq.o2switch.fr/cpanel/emails/delivrabilite-spf-dkim/',
  },
  {
    key: 'infomaniak', name: 'Infomaniak', include: 'spf.infomaniak.ch', cost: 3, mx: /(^|\.)infomaniak\.(ch|com)$/,
    note: msg('Infomaniak publie lui-même v=spf1 include:spf.infomaniak.ch -all quand la zone DNS est chez lui.'),
    keywords: 'infomaniak kmail suisse', docs: 'https://www.infomaniak.com/fr/support/faq/2199/gerer-les-enregistrements-spf',
  },
  {
    key: 'zoho', name: 'Zoho Mail', include: 'zoho.com', cost: 5, mx: /(^|\.)zoho(mail)?\.(com|eu|in)$/,
    note: msg("Valeur de la documentation Zoho. Compte au centre de données européen : recopiez la valeur affichée dans la console d'administration."),
    keywords: 'zoho mail zohomail', docs: 'https://www.zoho.com/mail/help/adminconsole/spf-configuration.html',
  },
  {
    key: 'proton', name: 'Proton Mail', include: '_spf.protonmail.ch', cost: 2, mx: /(^|\.)protonmail\.ch$/,
    keywords: 'proton protonmail', docs: 'https://proton.me/support/anti-spoofing-custom-domain',
  },
  {
    key: 'postmark', name: 'Postmark',
    elsewhere: msg('Postmark ne demande plus de SPF : créez plutôt le CNAME de Return-Path personnalisé vers pm.mtasv.net indiqué dans Sender Signatures, DNS Settings.'),
    keywords: 'postmark activecampaign transactionnel',
  },
  {
    key: 'mailgun', name: 'Mailgun', include: 'mailgun.org', cost: 5,
    elsewhere: msg("Mailgun : l'include va sur le domaine d'envoi déclaré dans Mailgun, souvent un sous-domaine comme mg.<domaine>."),
    keywords: 'mailgun sinch transactionnel', docs: 'https://documentation.mailgun.com/docs/mailgun/user-manual/domains/domains-verify',
  },
  {
    key: 'hubspot', name: 'HubSpot',
    accountInclude: {
      placeholder: '123456.spf03.hubspotemail.net', pattern: /^\d+\.spf\d+\.hubspotemail\.net$/i,
      hint: msg('Include propre à votre compte : Settings, Content, Domains & URLs, Email Sending.'),
    },
    keywords: 'hubspot crm marketing', docs: 'https://knowledge.hubspot.com/marketing-email/manage-email-authentication-in-hubspot',
  },
  {
    key: 'ionos', name: 'IONOS', include: '_spf-eu.ionos.com', cost: 1, mx: /(^|\.)(ionos\.[a-z.]+|kundenserver\.de)$/,
    note: msg('Avec les serveurs DNS IONOS, activez plutôt leur enregistrement « IONOS SPF (TXT) ».'),
    keywords: 'ionos 1and1 1&1',
  },
  {
    key: 'gandi', name: 'Gandi', include: '_mailcust.gandi.net', cost: 2, mx: /(^|\.)gandi\.net$/,
    extra: { include: '_spf.gpaas.net', cost: 2, label: msg('Site web hébergé chez Gandi qui envoie aussi') },
    keywords: 'gandi', docs: 'https://helpdesk.gandi.net/hc/fr/articles/14023116166172-Enregistrement-SPF',
  },
];

export const providerByKey = (k: string) => SPF_PROVIDERS.find((p) => p.key === k);

/** Provider whose official include (or old alias, or account pattern) is this domain. */
export function providerOfInclude(target: string): SpfProvider | undefined {
  const t = target.toLowerCase().replace(/\.$/, '');
  return SPF_PROVIDERS.find(
    (p) => p.include === t || p.aliases?.includes(t) || p.extra?.include === t || p.accountInclude?.pattern.test(t) || (p.key === 'ovh' && t === 'mx.ovh.ca'),
  );
}

/** Providers revealed by the MX hosts of the domain. */
export function providersFromMx(mx: string[]): { provider: SpfProvider; host: string }[] {
  const out: { provider: SpfProvider; host: string }[] = [];
  for (const p of SPF_PROVIDERS) {
    if (!p.mx) continue;
    const host = mx.find((h) => p.mx!.test(h.toLowerCase().replace(/\.$/, '')));
    if (host) out.push({ provider: p, host });
  }
  return out;
}

const norm = (s: string) => s.normalize('NFD').replace(/\p{M}/gu, '').toLowerCase();

/** Search box: providers whose name or keywords contain every typed word. */
export function searchProviders(q: string, exclude: Set<string>): SpfProvider[] {
  const words = norm(q).split(/\s+/).filter(Boolean);
  if (!words.length) return [];
  return SPF_PROVIDERS.filter((p) => !exclude.has(p.key)).filter((p) => {
    const hay = norm(`${p.name} ${p.keywords} ${p.include ?? ''}`);
    return words.every((w) => hay.includes(w));
  });
}
