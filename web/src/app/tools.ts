// Tool catalogue: navigation, command search and routes. Pages live in src/tools/<id>/Page.tsx.
import type { LucideIcon } from 'lucide-react';
import { msg } from '../lib/i18n';
import {
  AtSign, BadgeCheck, BookLock, CornerDownRight, ListTree, Binary, FileBarChart, FileKey2, Fingerprint, Globe2, History, KeyRound, Link2,
  MailCheck, Network, Radar, Search, Server, ShieldCheck, ShieldQuestion, Sparkles, Stamp, Trash2, Waypoints,
} from 'lucide-react';

export type Group = 'mail' | 'domaine' | 'dns' | 'reputation' | 'rapports' | 'generateurs' | 'outils';

export interface ToolMeta {
  id: string;
  title: string;
  /** Short label for the rail. */
  nav: string;
  description: string;
  group: Group;
  /** Base path; pages may add a parameter (/spf/:domain). */
  path: string;
  /** Route pattern(s) relative to root. */
  routes: string[];
  icon: LucideIcon;
  /** Usable without password. */
  public?: boolean;
  /** Words matched by the command search. */
  keywords?: string;
}

export const GROUPS: { id: Group; title: string }[] = [
  { id: 'mail', title: msg('Mail') },
  { id: 'domaine', title: msg('Domaine') },
  { id: 'dns', title: msg('DNS') },
  { id: 'reputation', title: msg('Réputation') },
  { id: 'rapports', title: msg('Rapports') },
  { id: 'generateurs', title: msg('Générateurs') },
  { id: 'outils', title: msg('Outils') },
];

export const TOOLS: ToolMeta[] = [
  { id: 'mail', title: msg('Test de mail'), nav: msg('Test de mail'), group: 'mail', path: '/mail', routes: ['/mail', '/mail/:addressId', '/mail/message/:messageId'], icon: MailCheck,
    description: msg("Envoyez un message à l'adresse affichée : le compte rendu arrive tout seul."), keywords: 'mail tester spam score spamassassin envoi' },
  { id: 'mail-analyze', title: msg('Analyser des en-têtes ou un .eml'), nav: msg('En-têtes et .eml'), group: 'mail', path: '/mail/analyse', routes: ['/mail/analyse'], icon: FileKey2,
    description: msg('Collez des en-têtes ou déposez un fichier .eml.'), keywords: 'headers en-têtes eml received analyse message' },
  { id: 'domain', title: msg('Scanner de domaine'), nav: msg('Scanner'), group: 'domaine', path: '/domaine', routes: ['/domaine', '/domaine/:domain'], icon: Radar,
    description: msg('Tout ce qui fait arriver les mails d’un domaine, en une mesure.'), keywords: 'domain scanner audit complet' },
  { id: 'spf', title: msg('SPF'), nav: msg('SPF'), group: 'domaine', path: '/spf', routes: ['/spf', '/spf/:domain'], icon: ShieldCheck,
    description: msg('Arbre des include, compte des requêtes DNS, IP autorisées.'), keywords: 'spf checker include lookup' },
  { id: 'dkim', title: msg('DKIM'), nav: msg('DKIM'), group: 'domaine', path: '/dkim', routes: ['/dkim', '/dkim/:domain'], icon: KeyRound,
    description: msg('Découverte des sélecteurs et contrôle des clés.'), keywords: 'dkim selecteur selector cle key' },
  { id: 'dmarc', title: msg('DMARC'), nav: msg('DMARC'), group: 'domaine', path: '/dmarc', routes: ['/dmarc', '/dmarc/:domain'], icon: Fingerprint,
    description: msg('Politique, alignement, adresses de rapports.'), keywords: 'dmarc checker policy politique' },
  { id: 'bimi', title: msg('BIMI'), nav: msg('BIMI'), group: 'domaine', path: '/bimi', routes: ['/bimi', '/bimi/:domain'], icon: BadgeCheck,
    description: msg('Logo SVG, certificat VMC ou CMC, prérequis DMARC.'), keywords: 'bimi logo vmc cmc svg' },
  { id: 'mta-sts', title: msg('MTA-STS et TLS-RPT'), nav: msg('MTA-STS'), group: 'domaine', path: '/mta-sts', routes: ['/mta-sts', '/mta-sts/:domain'], icon: Stamp,
    description: msg('Politique de chiffrement des MX et rapports TLS.'), keywords: 'mta-sts tls-rpt tls' },
  { id: 'smtp', title: msg('Serveurs SMTP'), nav: msg('SMTP'), group: 'domaine', path: '/smtp', routes: ['/smtp', '/smtp/:domain'], icon: Server,
    description: msg('Bannière, STARTTLS et certificat de chaque MX.'), keywords: 'smtp starttls mx test connexion' },
  { id: 'subdomains', title: msg('Sous-domaines'), nav: msg('Sous-domaines'), group: 'dns', path: '/sous-domaines', routes: ['/sous-domaines', '/sous-domaines/:domain'], icon: ListTree,
    description: msg('Les sous-domaines révélés par les certificats publiés, et ce qu’ils résolvent maintenant.'), keywords: 'sous-domaine subdomain certificat certificate transparency crt.sh ct logs takeover' },
  { id: 'dns', title: msg('Recherche DNS'), nav: msg('Recherche DNS'), group: 'dns', path: '/dns', routes: ['/dns', '/dns/:name'], icon: Search,
    description: msg('Réponse des serveurs autoritaires, trace de résolution, format dig.'), keywords: 'dns lookup dig record enregistrement a mx txt' },
  { id: 'propagation', title: msg('Propagation DNS'), nav: msg('Propagation'), group: 'dns', path: '/propagation', routes: ['/propagation', '/propagation/:name'], icon: Globe2,
    description: msg('Ce que voient les résolveurs du monde, face à la vérité autoritaire.'), keywords: 'propagation dns monde resolveurs gdnspc whatsmydns' },
  { id: 'dnssec', title: msg('DNSSEC'), nav: msg('DNSSEC'), group: 'dns', path: '/dnssec', routes: ['/dnssec', '/dnssec/:domain'], icon: Binary,
    description: msg('Chaîne de confiance du parent à la zone.'), keywords: 'dnssec ds dnskey rrsig' },
  { id: 'rdap', title: msg('Whois et RDAP'), nav: msg('Whois'), group: 'dns', path: '/whois', routes: ['/whois', '/whois/:domain', '/rdap', '/rdap/:domain'], icon: AtSign,
    description: msg('Registre et bureau d’enregistrement comparés : dates, statuts, contacts. Un domaine ou une liste.'),
    keywords: 'whois rdap registrar registre bureau enregistrement expiration age creation statut epp contact titulaire revendeur reseller liste csv' },
  { id: 'ip', title: msg('Réputation'), nav: msg('IP et domaine'), group: 'reputation', path: '/ip', routes: ['/ip', '/ip/:ip', '/ip/:ip/:prefix'], icon: Network,
    description: msg("Une IP ou un domaine : listes noires, réputation des adresses du site et des MX, âge, sources de sécurité."), keywords: 'ip domaine blacklist liste noire reputation dnsbl dbl surbl uribl' },
  { id: 'link', title: msg('Vérifier un lien'), nav: msg('Liens'), group: 'reputation', path: '/lien', routes: ['/lien'], icon: Link2,
    description: msg('Redirections suivies en direct, phishing, logiciels malveillants.'), keywords: 'phishing lien url redirection malware' },
  { id: 'redirects', title: msg('Redirections'), nav: msg('Redirections'), group: 'reputation', path: '/redirections', routes: ['/redirections'], icon: CornerDownRight,
    description: msg('Chaque saut : statut, en-têtes, corps HTML, temps, certificat.'), keywords: 'redirection redirect 301 302 307 308 http header en-tete chaine canonical www https' },
  { id: 'dmarc-reports', title: msg('Rapports DMARC'), nav: msg('Rapports DMARC'), group: 'rapports', path: '/rapports-dmarc', routes: ['/rapports-dmarc'], icon: FileBarChart,
    description: msg('Déposez vos rapports agrégés : qui envoie en votre nom.'), keywords: 'dmarc report rapport xml rua analyzer' },
  { id: 'gen-spf', title: msg('Générateur SPF'), nav: msg('SPF'), group: 'generateurs', path: '/generateurs/spf', routes: ['/generateurs/spf'], icon: Sparkles, public: true,
    description: msg('Composez un SPF valide, le compteur de requêtes sous les yeux.'), keywords: 'generer spf generator creer' },
  { id: 'gen-dkim', title: msg('Générateur DKIM'), nav: msg('DKIM'), group: 'generateurs', path: '/generateurs/dkim', routes: ['/generateurs/dkim'], icon: Sparkles, public: true,
    description: msg('Paire de clés générée dans votre navigateur.'), keywords: 'generer dkim cle key generator' },
  { id: 'gen-dmarc', title: msg('Générateur DMARC'), nav: msg('DMARC'), group: 'generateurs', path: '/generateurs/dmarc', routes: ['/generateurs/dmarc'], icon: Sparkles, public: true,
    description: msg('Une politique progressive, de none à reject.'), keywords: 'generer dmarc generator politique' },
  { id: 'gen-mta-sts', title: msg('Générateur MTA-STS'), nav: msg('MTA-STS'), group: 'generateurs', path: '/generateurs/mta-sts', routes: ['/generateurs/mta-sts'], icon: Sparkles, public: true,
    description: msg('Enregistrements et fichier de politique.'), keywords: 'generer mta-sts tls-rpt' },
  { id: 'history', title: msg('Historique'), nav: msg('Historique'), group: 'outils', path: '/historique', routes: ['/historique'], icon: History,
    description: msg('Vos mesures des trois derniers mois.'), keywords: 'historique history' },
  { id: 'caches', title: msg('Vider les caches'), nav: msg('Vider les caches'), group: 'outils', path: '/caches', routes: ['/caches'], icon: Trash2,
    description: msg('Caches DNS et cache de pages, sur le serveur et sur votre poste.'), keywords: 'cache flush vider dns purge' },
  { id: 'carnet', title: msg('Mon carnet'), nav: msg('Mon carnet'), group: 'outils', path: '/carnet', routes: ['/carnet'], icon: BookLock,
    description: msg('Ce que ce navigateur garde, vos appareils reliés, effacer vos traces.'), keywords: 'carnet appareil appareils données donnees effacer traces confidentialité confidentialite vie privée relier lier' },
];

/** The read-only report of a mail message shared by link: a route, not a tool of the menus. */
export const SHARED_REPORT: ToolMeta = {
  id: 'shared', title: msg('Compte rendu partagé'), nav: msg('Partage'), group: 'mail', path: '/partage', routes: ['/partage/:token'], icon: Link2,
  description: msg('Un compte rendu de test de mail ouvert par un lien de partage.'),
};

export const toolById = (id: string) => TOOLS.find((t) => t.id === id);

/** Class that gives an element the hue of a tool family (--fam), see .fam--* in signal.css. */
export const famClass = (group: Group | undefined) => (group ? `fam--${group}` : '');

/** The tool whose page is at this path, if any (the home page is none). */
export const toolAt = (pathname: string) =>
  TOOLS.find((t) => t.path !== '/' && (pathname === t.path || pathname.startsWith(t.path + '/')));

export const PHISHING_ICON = ShieldQuestion;
export const ROUTE_ICON = Waypoints;
