// Sending providers and forwarding services recognised from a PTR or a DKIM signing domain.
import { msg } from '../../i18n.js';

export interface Provider {
  key: string;
  name: string;
  ptr: RegExp[];
  dkim: RegExp[];
  /** SPF include to add (when the provider publishes a stable one). */
  spfInclude?: string;
  /** Where to turn on the DKIM signature of the customer domain. */
  dkimHint: string;
  spfHint?: string;
}

const d = (...names: string[]) => names.map((n) => new RegExp('(^|\\.)' + n.replace(/\./g, '\\.') + '$', 'i'));

export const PROVIDERS: Provider[] = [
  {
    key: 'google_workspace', name: 'Google (Workspace, Gmail)',
    ptr: d('google.com', 'googlemail.com', 'googleusercontent.com', '1e100.net'),
    dkim: d('google.com', 'gmail.com'),
    spfInclude: '_spf.google.com',
    dkimHint: msg("Dans la console d'administration Google, ouvrez Applications, Google Workspace, Gmail, Authentifier les e-mails, générez la clé DKIM de votre domaine, publiez l'enregistrement TXT indiqué, puis cliquez sur Démarrer l'authentification."),
  },
  {
    key: 'microsoft_365', name: 'Microsoft (365, Outlook)',
    ptr: d('outlook.com', 'protection.outlook.com', 'hotmail.com', 'microsoft.com'),
    dkim: d('onmicrosoft.com', 'outlook.com', 'microsoft.com'),
    spfInclude: 'spf.protection.outlook.com',
    dkimHint: msg("Dans le portail Microsoft Defender, ouvrez Courrier électronique et collaboration, Stratégies, Paramètres d'authentification DKIM, choisissez votre domaine, publiez les deux CNAME selector1 et selector2 indiqués, puis activez la signature."),
  },
  {
    key: 'brevo', name: 'Brevo (Sendinblue)',
    ptr: d('brevo.com', 'sendinblue.com', 'sendib.com', 'sendibt.com', 'sibmail.com'),
    dkim: d('brevo.com', 'sendinblue.com', 'sendib.com'),
    spfInclude: 'spf.brevo.com',
    dkimHint: msg("Chez Brevo, ouvrez Expéditeurs, domaines et IP dédiées, Domaines, authentifiez votre domaine et publiez l'enregistrement DKIM (brevo1._domainkey) indiqué."),
  },
  {
    key: 'mailchimp', name: 'Mailchimp et Mandrill',
    ptr: d('mcsv.net', 'mcdlv.net', 'mailchimp.com', 'mandrillapp.com', 'rsgsv.net'),
    dkim: d('mcsv.net', 'mailchimp.com', 'mandrillapp.com'),
    spfInclude: 'servers.mcsv.net',
    dkimHint: msg("Chez Mailchimp, ouvrez Paramètres, Domaines, authentifiez votre domaine d'envoi et publiez les enregistrements DKIM (k2._domainkey, k3._domainkey) indiqués."),
  },
  {
    key: 'sendgrid', name: 'SendGrid',
    ptr: d('sendgrid.net', 'sendgrid.com'),
    dkim: d('sendgrid.net', 'sendgrid.com'),
    spfInclude: 'sendgrid.net',
    dkimHint: msg("Chez SendGrid, ouvrez Settings, Sender Authentication, lancez Authenticate Your Domain et publiez les CNAME fournis (ils activent le DKIM et l'enveloppe alignés)."),
  },
  {
    key: 'amazon_ses', name: 'Amazon SES',
    ptr: d('amazonses.com', 'amazonaws.com'),
    dkim: d('amazonses.com'),
    spfInclude: 'amazonses.com',
    dkimHint: msg("Dans Amazon SES, ouvrez Verified identities, choisissez votre domaine, activez Easy DKIM et publiez les trois CNAME fournis. Configurez aussi un domaine MAIL FROM personnalisé pour aligner le SPF."),
  },
  {
    key: 'mailjet', name: 'Mailjet',
    ptr: d('mailjet.com', 'mailjet.net'),
    dkim: d('mailjet.com'),
    spfInclude: 'spf.mailjet.com',
    dkimHint: msg("Chez Mailjet, ouvrez Account settings, Sender domains and addresses, validez votre domaine et publiez l'enregistrement DKIM (mailjet._domainkey) indiqué."),
  },
  {
    key: 'mailgun', name: 'Mailgun',
    ptr: d('mailgun.org', 'mailgun.net'),
    dkim: d('mailgun.org'),
    spfInclude: 'mailgun.org',
    dkimHint: msg("Chez Mailgun, ouvrez Sending, Domains, votre domaine, et publiez les enregistrements DNS DKIM indiqués."),
  },
  {
    key: 'postmark', name: 'Postmark',
    ptr: d('postmarkapp.com', 'mtasv.net'),
    dkim: d('postmarkapp.com', 'pm-bounces.com'),
    spfInclude: 'spf.mtasv.net',
    dkimHint: msg("Chez Postmark, ouvrez Sender Signatures ou Domains, ajoutez votre domaine et publiez l'enregistrement DKIM indiqué."),
  },
  {
    key: 'ovh', name: 'OVHcloud',
    ptr: d('ovh.net', 'ovh.com', 'ovh.fr', 'mail.ovh.net'),
    dkim: d('ovh.net', 'ovh.com'),
    spfInclude: 'mx.ovh.com',
    dkimHint: msg("Dans l'espace client OVHcloud, ouvrez la zone DNS du domaine et activez DKIM pour l'offre e-mail concernée (bouton de configuration DKIM de l'offre MX Plan ou Email Pro)."),
  },
  {
    key: 'o2switch', name: 'o2switch',
    ptr: d('o2switch.net', 'o2switch.fr'),
    dkim: d('o2switch.net'),
    dkimHint: msg("Dans cPanel, ouvrez Email Deliverability (Délivrabilité des e-mails), sélectionnez votre domaine et corrigez ou installez l'enregistrement DKIM proposé."),
    spfHint: msg("Autorisez l'adresse IP de votre serveur o2switch dans le SPF (mécanisme ip4: ou ip6: avec l'adresse vue dans le rapport), ou utilisez le correctif proposé par Email Deliverability de cPanel."),
  },
];

/** Services that relay mail without rewriting the envelope: SPF fails there by construction. */
export const FORWARDERS: RegExp[] = [
  ...d('improvmx.com', 'forwardemail.net', 'simplelogin.co', 'simplelogin.io', 'addy.io', 'anonaddy.me', 'mailfence.com', 'googlegroups.com', 'groups.io', 'mailman.org'),
  /(^|\.)(forward|relay|mxforward|mail-forward)[0-9-]*\./i,
];

export interface ProviderMatch {
  key: string;
  name: string;
}

export function providerByPtr(ptr: string | null | undefined): Provider | undefined {
  if (!ptr) return undefined;
  const h = ptr.replace(/\.$/, '');
  return PROVIDERS.find((p) => p.ptr.some((r) => r.test(h)));
}

export function providerByDkimDomain(dom: string): Provider | undefined {
  return PROVIDERS.find((p) => p.dkim.some((r) => r.test(dom)));
}

export function isForwarderPtr(ptr: string | null | undefined): boolean {
  return !!ptr && FORWARDERS.some((r) => r.test(ptr.replace(/\.$/, '')));
}

export const providerByKey = (k: string) => PROVIDERS.find((p) => p.key === k);
