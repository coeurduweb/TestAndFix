// Common DKIM selectors tried by the discovery, each with where it comes from.
// confirmed: true = named on the provider's official documentation (pages opened on 2026-11-10).
// confirmed: false = seen in third-party guides or generic usage only; kept because they are
// cheap to try, but never presented as the provider's documented selector.

export interface KnownSelector {
  selector: string;
  /** Provider keys (knowledge/SCHEMA.md list when it exists there). */
  providers: string[];
  /** URL of the official documentation, or a short note for unofficial entries. */
  source: string;
  confirmed?: boolean;
  /** TXT with the key, or CNAME delegated to the provider. */
  type?: 'TXT' | 'CNAME';
  note?: string;
}

const MS = 'https://learn.microsoft.com/en-us/defender-office-365/email-authentication-dkim-configure';
const GENERIC = 'usage courant, aucun fournisseur ne le documente';

export const COMMON_SELECTORS: KnownSelector[] = [
  // --- confirmed on official pages
  { selector: 'google', providers: ['google_workspace'], type: 'TXT', confirmed: true, source: 'https://knowledge.workspace.google.com/admin/security/set-up-dkim', note: 'préfixe par défaut, modifiable' },
  { selector: 'selector1', providers: ['microsoft_365'], type: 'CNAME', confirmed: true, source: MS },
  { selector: 'selector2', providers: ['microsoft_365'], type: 'CNAME', confirmed: true, source: MS },
  { selector: 'mte1', providers: ['mailchimp'], type: 'CNAME', confirmed: true, source: 'https://mailchimp.com/developer/transactional/docs/authentication-delivery/', note: 'Mailchimp Transactional (Mandrill)' },
  { selector: 'mte2', providers: ['mailchimp'], type: 'CNAME', confirmed: true, source: 'https://mailchimp.com/developer/transactional/docs/authentication-delivery/', note: 'Mailchimp Transactional (Mandrill)' },
  { selector: 's1', providers: ['sendgrid'], type: 'CNAME', confirmed: true, source: 'https://www.twilio.com/docs/sendgrid/ui/account-and-settings/how-to-set-up-domain-authentication' },
  { selector: 's2', providers: ['sendgrid'], type: 'CNAME', confirmed: true, source: 'https://www.twilio.com/docs/sendgrid/ui/account-and-settings/how-to-set-up-domain-authentication' },
  { selector: 'm1', providers: ['sendgrid'], type: 'TXT', confirmed: true, source: 'https://www.twilio.com/docs/sendgrid/ui/account-and-settings/dkim-records', note: 'mode manuel' },
  { selector: 'pdk1', providers: ['mailgun'], type: 'CNAME', confirmed: true, source: 'https://documentation.mailgun.com/docs/mailgun/user-manual/domains/dkim_security' },
  { selector: 'pdk2', providers: ['mailgun'], type: 'CNAME', confirmed: true, source: 'https://documentation.mailgun.com/docs/mailgun/user-manual/domains/dkim_security' },
  { selector: 'pm', providers: ['postmark'], type: 'TXT', confirmed: true, source: 'https://postmarkapp.com/support/article/troubleshooting-dkim-issues-in-postmark', note: 'les comptes récents utilisent un sélecteur horodaté (…pm) non devinable' },
  { selector: 'protonmail', providers: ['proton'], type: 'CNAME', confirmed: true, source: 'https://proton.me/support/custom-domain-cloudflare' },
  { selector: 'protonmail2', providers: ['proton'], type: 'CNAME', confirmed: true, source: 'https://proton.me/support/custom-domain-cloudflare' },
  { selector: 'protonmail3', providers: ['proton'], type: 'CNAME', confirmed: true, source: 'https://proton.me/support/custom-domain-cloudflare' },
  { selector: 'default', providers: ['cpanel', 'o2switch'], type: 'TXT', confirmed: true, source: 'https://api.docs.cpanel.net/openapi/cpanel/operation/validate_current_dkims/', note: 'cPanel ; o2switch utilise cPanel (page o2switch non trouvée)' },
  { selector: 'fm1', providers: ['fastmail'], type: 'CNAME', confirmed: true, source: 'https://www.fastmail.help/hc/en-us/articles/360060591153-Manual-DNS-configuration' },
  { selector: 'fm2', providers: ['fastmail'], type: 'CNAME', confirmed: true, source: 'https://www.fastmail.help/hc/en-us/articles/360060591153-Manual-DNS-configuration' },
  { selector: 'fm3', providers: ['fastmail'], type: 'CNAME', confirmed: true, source: 'https://www.fastmail.help/hc/en-us/articles/360060591153-Manual-DNS-configuration' },
  { selector: 's1-ionos', providers: ['ionos'], type: 'CNAME', confirmed: true, source: 'https://www.ionos.com/help/domains/configuring-mail-servers-and-other-related-records/email-authentication-with-dkim' },
  { selector: 's2-ionos', providers: ['ionos'], type: 'CNAME', confirmed: true, source: 'https://www.ionos.com/help/domains/configuring-mail-servers-and-other-related-records/email-authentication-with-dkim' },
  { selector: 's42582890', providers: ['ionos'], type: 'CNAME', confirmed: true, source: 'https://www.ionos.com/help/domains/configuring-mail-servers-and-other-related-records/email-authentication-with-dkim' },
  { selector: 'gm1', providers: ['gandi'], type: 'CNAME', confirmed: true, source: 'https://docs.gandi.net/en/gandimail/common_operations/enable_antispoofing_tools.html' },
  { selector: 'gm2', providers: ['gandi'], type: 'CNAME', confirmed: true, source: 'https://docs.gandi.net/en/gandimail/common_operations/enable_antispoofing_tools.html' },
  { selector: 'gm3', providers: ['gandi'], type: 'CNAME', confirmed: true, source: 'https://docs.gandi.net/en/gandimail/common_operations/enable_antispoofing_tools.html' },
  ...['km1', 'km2', 'km3', 'km4', 'kt1', 'kt2', 'ks1', 'ks2', 'kl1', 'kl2'].map(
    (selector): KnownSelector => ({ selector, providers: ['klaviyo'], type: 'CNAME', confirmed: true, source: 'https://help.klaviyo.com/hc/en-us/articles/dns-and-spf-setup-troubleshooting-in-klaviyo' }),
  ),
  { selector: 'zendesk1', providers: ['zendesk'], type: 'CNAME', confirmed: true, source: 'https://support.zendesk.com/hc/en-us/articles/4408822303386' },
  { selector: 'zendesk2', providers: ['zendesk'], type: 'CNAME', confirmed: true, source: 'https://support.zendesk.com/hc/en-us/articles/4408822303386' },
  { selector: 'litesrv', providers: ['mailerlite'], type: 'CNAME', confirmed: true, source: 'https://www.mailerlite.com/help/troubleshooting-domain-authentication' },
  { selector: 'ctct1', providers: ['constant_contact'], type: 'CNAME', confirmed: true, source: 'https://knowledgebase.constantcontact.com/articles/KnowledgeBase/39520-Set-Up-the-Self-Authentication-DKIM-Key-with-Your-Hosting-Provider?lang=en_US' },
  { selector: 'ctct2', providers: ['constant_contact'], type: 'CNAME', confirmed: true, source: 'https://knowledgebase.constantcontact.com/articles/KnowledgeBase/39520-Set-Up-the-Self-Authentication-DKIM-Key-with-Your-Hosting-Provider?lang=en_US' },
  { selector: 'cm', providers: ['campaign_monitor'], type: 'TXT', confirmed: true, source: 'https://help.campaignmonitor.com/s/article/manage-your-own-authentication' },
  { selector: 'api', providers: ['elastic_email'], type: 'TXT', confirmed: true, source: 'https://help.elasticemail.com/en/articles/4934400-how-to-verify-your-domain' },
  { selector: 'zoho', providers: ['zoho'], type: 'TXT', confirmed: true, source: 'https://www.zoho.com/mail/help/adminconsole/dkim-configuration.html', note: 'exemple de la documentation : le sélecteur Zoho est choisi par l’administrateur' },

  // --- third-party guides only (official page unreachable or silent)
  { selector: 'k1', providers: ['mailchimp'], type: 'CNAME', confirmed: false, source: 'guides tiers ; la page Mailchimp ne nomme pas les sélecteurs' },
  { selector: 'k2', providers: ['mailchimp'], type: 'CNAME', confirmed: false, source: 'guides tiers ; la page Mailchimp ne nomme pas les sélecteurs' },
  { selector: 'k3', providers: ['mailchimp'], type: 'CNAME', confirmed: false, source: 'guides tiers ; la page Mailchimp ne nomme pas les sélecteurs' },
  { selector: 'mandrill', providers: ['mailchimp'], confirmed: false, source: 'guides tiers (anciens comptes Mandrill)' },
  { selector: 'brevo1', providers: ['brevo'], type: 'CNAME', confirmed: false, source: 'guides tiers ; documentation Brevo inaccessible lors de la vérification' },
  { selector: 'brevo2', providers: ['brevo'], type: 'CNAME', confirmed: false, source: 'guides tiers ; documentation Brevo inaccessible lors de la vérification' },
  { selector: 'mail', providers: ['brevo'], type: 'TXT', confirmed: false, source: 'guides tiers (ancien Sendinblue) et usage courant' },
  { selector: 'mailjet', providers: ['mailjet'], type: 'TXT', confirmed: false, source: 'guides tiers ; documentation Mailjet inaccessible lors de la vérification' },
  { selector: 'zmail', providers: ['zoho'], type: 'TXT', confirmed: false, source: 'guides tiers' },
  { selector: 'ml', providers: ['mailerlite'], confirmed: false, source: 'guides tiers (MailerLite Classic)' },
  { selector: 'smtpapi', providers: ['hubspot'], confirmed: false, source: 'cité en exemple par https://knowledge.hubspot.com/marketing-email/manage-email-authentication-in-hubspot' },
  { selector: 'hs1', providers: ['hubspot'], confirmed: false, source: 'guides tiers' },
  { selector: 'hs2', providers: ['hubspot'], confirmed: false, source: 'guides tiers' },
  { selector: '200608', providers: ['salesforce'], confirmed: false, source: 'guide tiers (Valimail)' },
  { selector: 's1024', providers: [], confirmed: false, source: GENERIC },
  { selector: 's2048', providers: [], confirmed: false, source: GENERIC },

  // --- seen published on gmail.com and google.com (checked 2026-11-10), not documented by Google
  ...['20230601', '20221208', '20210112', '20161025', '20120113'].map(
    (selector): KnownSelector => ({ selector, providers: ['google_workspace'], confirmed: false, source: 'observé sur gmail.com et google.com le 2026-11-10 (non documenté)' }),
  ),

  // --- generic names often chosen by hand (servers, panels, scripts)
  ...['dkim', 'smtp', 'mx', 'email', 'selector', 'key1', 'key2', 'dk', 'x', 'mail1', 'mail2', 'main', 'sig1', 'everlytickey1', 'everlytickey2', 'mxvault', 'scph0123', 'mailo', 'sendinblue', 'turbo-smtp', 'ovh', 'o2switch', 'infomaniak', 'mailchannels', 'resend', 'amazonses', 'sib', 'mailer', 'dkim1', 'dkim2', 'k4', 'krs', 'pic', 'cloudflare', '2024', '2025', '2026', '202401', '202501', '202601'].map(
    (selector): KnownSelector => ({ selector, providers: [], confirmed: false, source: GENERIC }),
  ),
];
