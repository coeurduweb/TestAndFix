// Subdomain takeover fingerprints. Source: the can-i-take-over-xyz project
// (https://github.com/EdOverflow/can-i-take-over-xyz, fingerprints.json read on 2026-11-11):
// service, status ("Vulnerable" / "Edge case" / "Not vulnerable"), CNAME targets, the error text
// the service serves for an unclaimed name, or NXDOMAIN when the target itself disappears.
// Only "Vulnerable" and "Edge case" services are kept. When fingerprints.json gives no CNAME target,
// the suffix comes from the provider's own documentation (checked the same day, URL beside it).
// Services whose fingerprint is only an HTTP status (Helprace, LaunchRock) or an empty string are left
// out: they would flag healthy sites.
import { msg } from '../../i18n.js';

export type TakeoverLevel = 'vulnerable' | 'edge';

export interface TakeoverService {
  service: string;
  level: TakeoverLevel;
  /** Suffixes of the CNAME target ("github.io" matches "x.github.io"). */
  suffixes: string[];
  /** Text of the page served for an unclaimed name; undefined when the sign is NXDOMAIN. */
  fingerprint?: RegExp;
  /** The target name stops existing when the resource is deleted. */
  nxdomain?: boolean;
  /** What to recreate, in French, for the fix. */
  resource: string;
  references: string[];
}

const CIOTX = 'https://github.com/EdOverflow/can-i-take-over-xyz';
const issue = (n: number) => `${CIOTX}/issues/${n}`;

export const TAKEOVER_SERVICES: TakeoverService[] = [
  { service: 'Amazon S3', level: 'vulnerable', suffixes: ['s3.amazonaws.com'], fingerprint: /NoSuchBucket|The specified bucket does not exist/,
    resource: msg('le compartiment (bucket) S3 du même nom'), references: [issue(36), 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/WebsiteEndpoints.html'] },
  { service: 'AWS Elastic Beanstalk', level: 'vulnerable', suffixes: ['elasticbeanstalk.com'], nxdomain: true,
    resource: msg("l'environnement Elastic Beanstalk"), references: [issue(194)] },
  { service: 'Microsoft Azure', level: 'vulnerable', nxdomain: true,
    suffixes: ['cloudapp.net', 'cloudapp.azure.com', 'azurewebsites.net', 'blob.core.windows.net', 'azure-api.net', 'azurehdinsight.net', 'azureedge.net',
      'azurecontainer.io', 'database.windows.net', 'azuredatalakestore.net', 'search.windows.net', 'azurecr.io', 'redis.cache.windows.net', 'servicebus.windows.net', 'visualstudio.com'],
    resource: msg('la ressource Azure (application, stockage, CDN...)'), references: [issue(35), 'https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover'] },
  { service: 'GitHub Pages', level: 'edge', suffixes: ['github.io'], fingerprint: /There isn't a GitHub Pages site here\./,
    resource: msg('le dépôt GitHub Pages avec ce domaine personnalisé'),
    references: [issue(37), 'https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/verifying-your-custom-domain-for-github-pages'] },
  { service: 'Heroku', level: 'edge', suffixes: ['herokuapp.com', 'herokudns.com', 'herokussl.com'], fingerprint: /No such app/,
    resource: msg("l'application Heroku avec ce domaine"), references: [issue(38), 'https://devcenter.heroku.com/articles/custom-domains'] },
  { service: 'Shopify', level: 'edge', suffixes: ['myshopify.com'], fingerprint: /Sorry, this shop is currently unavailable\./,
    resource: msg('la boutique Shopify avec ce domaine'), references: [issue(32), 'https://help.shopify.com/en/manual/domains/add-a-domain/connecting-domains/connect-domain-manual'] },
  { service: 'Netlify', level: 'edge', suffixes: ['netlify.app', 'netlify.com'], fingerprint: /Not Found - Request ID:/,
    resource: msg('le site Netlify avec ce domaine'), references: [issue(40), 'https://docs.netlify.com/manage/domains/configure-domains/configure-external-dns/'] },
  { service: 'Vercel', level: 'edge', suffixes: ['vercel-dns.com', 'vercel.app'], fingerprint: /DEPLOYMENT_NOT_FOUND/,
    resource: msg('le projet Vercel avec ce domaine'), references: [issue(183), 'https://vercel.com/docs/domains/working-with-domains/add-a-domain'] },
  { service: 'Read the Docs', level: 'vulnerable', suffixes: ['readthedocs.io', 'readthedocs-hosted.com'],
    fingerprint: /The link you have followed or the URL that you entered does not exist\./,
    resource: msg('le projet Read the Docs avec ce domaine'), references: [issue(160), 'https://docs.readthedocs.io/en/stable/custom-domains.html'] },
  { service: 'Bitbucket', level: 'vulnerable', suffixes: ['bitbucket.io'], fingerprint: /Repository not found/, resource: msg('le dépôt Bitbucket Cloud'), references: [issue(97)] },
  { service: 'Ghost', level: 'vulnerable', suffixes: ['ghost.io'], fingerprint: /Site unavailable\.|Failed to resolve DNS path for this host/, resource: msg('le site Ghost(Pro)'), references: [issue(89)] },
  { service: 'Discourse', level: 'vulnerable', suffixes: ['trydiscourse.com'], nxdomain: true, resource: msg('le forum Discourse hébergé'), references: [issue(49)] },
  { service: 'Surge.sh', level: 'vulnerable', suffixes: ['surge.sh'], fingerprint: /project not found/, resource: msg('le projet Surge'), references: [issue(198)] },
  { service: 'ReadMe', level: 'vulnerable', suffixes: ['readme.io'], fingerprint: /The creators of this project are still working on making everything perfect!/, resource: msg('le projet ReadMe'), references: [issue(41)] },
  { service: 'WordPress.com', level: 'vulnerable', suffixes: ['wordpress.com'], fingerprint: /Do you want to register .*\.wordpress\.com\?/, resource: msg('le site WordPress.com'), references: [`${CIOTX}/pull/176`] },
  { service: 'Help Scout', level: 'vulnerable', suffixes: ['helpscoutdocs.com'], fingerprint: /No settings were found for this company:/, resource: msg('le site Help Scout Docs'), references: [CIOTX] },
  { service: 'Help Juice', level: 'vulnerable', suffixes: ['helpjuice.com'], fingerprint: /We could not find what you're looking for\./, resource: msg('la base Helpjuice'), references: [CIOTX] },
  { service: 'ngrok', level: 'vulnerable', suffixes: ['ngrok.io'], fingerprint: /Tunnel .*\.ngrok\.io not found/, resource: msg('le tunnel ngrok'), references: [issue(92)] },
  { service: 'Agile CRM', level: 'vulnerable', suffixes: ['agilecrm.com'], fingerprint: /Sorry, this page is no longer available\./, resource: msg('le compte Agile CRM'), references: [issue(145)] },
  { service: 'Anima', level: 'vulnerable', suffixes: ['animaapp.io'], fingerprint: /The page you were looking for does not exist\./, resource: msg('le site Anima'), references: [issue(126)] },
  { service: 'Gemfury', level: 'vulnerable', suffixes: ['furyns.com'], fingerprint: /404: This page could not be found\./, resource: msg('le compte Gemfury'), references: [issue(154)] },
  { service: 'Hatena Blog', level: 'vulnerable', suffixes: ['hatenablog.com'], fingerprint: /404 Blog is not found/, resource: msg('le blog Hatena'), references: [CIOTX] },
  { service: 'JetBrains YouTrack', level: 'vulnerable', suffixes: ['youtrack.cloud'], fingerprint: /is not a registered InCloud YouTrack/, resource: msg("l'instance YouTrack"), references: [`${CIOTX}/pull/107`] },
  { service: 'Strikingly', level: 'vulnerable', suffixes: ['s.strikinglydns.com'], fingerprint: /PAGE NOT FOUND\./, resource: msg('le site Strikingly'), references: [issue(58)] },
  { service: 'SurveySparrow', level: 'vulnerable', suffixes: ['surveysparrow.com'], fingerprint: /Account not found\./, resource: msg('le compte SurveySparrow'), references: [issue(281)] },
  { service: 'Uberflip', level: 'vulnerable', suffixes: ['read.uberflip.com'], fingerprint: /The URL you've accessed does not provide a hub\./, resource: msg('le hub Uberflip'), references: [issue(150)] },
  { service: 'UptimeRobot', level: 'vulnerable', suffixes: ['stats.uptimerobot.com'], fingerprint: /page not found/, resource: msg("la page d'état UptimeRobot"), references: [issue(45)] },
  { service: 'Worksites', level: 'vulnerable', suffixes: ['worksites.net'], fingerprint: /Sorry, but the website you(&rsquo;|')re looking for doesn(&rsquo;|')t exist\./, resource: msg('le site Worksites'), references: [issue(142)] },
];

const endsWith = (host: string, suffix: string) => host === suffix || host.endsWith('.' + suffix);

/** Service hosting `target` (a CNAME target), if it is one of the known takeover-prone services. */
export function serviceOf(target: string): TakeoverService | undefined {
  const t = target.toLowerCase().replace(/\.$/, '');
  for (const s of TAKEOVER_SERVICES) {
    if (s.service === 'Amazon S3') {
      // S3 endpoints: bucket.s3.amazonaws.com, s3.<region>.amazonaws.com, s3-website[-.]<region>.amazonaws.com
      if (/(^|\.)s3([.-][a-z0-9-]+)*\.amazonaws\.com$/.test(t) || /(^|\.)s3-website[.-][a-z0-9-]+\.amazonaws\.com$/.test(t)) return s;
      continue;
    }
    if (s.suffixes.some((x) => endsWith(t, x))) return s;
  }
  return undefined;
}

/** First service found along a CNAME chain (the last hop is checked first: it is the real host). */
export function serviceOfChain(chain: string[]): { service: TakeoverService; target: string } | undefined {
  for (const target of [...chain].reverse()) {
    const service = serviceOf(target);
    if (service) return { service, target };
  }
  return undefined;
}

/** Does this page body carry the service's "unclaimed" fingerprint? Returns the matched text. */
export function matchFingerprint(service: TakeoverService, body: string): string | undefined {
  if (!service.fingerprint) return undefined;
  const m = service.fingerprint.exec(body);
  return m ? m[0] : undefined;
}
