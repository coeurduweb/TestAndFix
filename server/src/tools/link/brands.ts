// Brands targeted by phishing in France, and the detection of domains that imitate them:
// homoglyphs (Cyrillic or Greek letters, accents, 0 for o, rn for m), typos (edit distance),
// the brand name used as a word of an unrelated domain, and a page title that names a brand
// the domain does not belong to.
import { domainToUnicode } from 'node:url';
import net from 'node:net';
import { orgDomain } from '../../lib/email-auth/common.js';

export interface Brand {
  id: string;
  /** Display name, used in the texts. */
  name: string;
  /** Words looked for in host names (lower case, ASCII). */
  keywords: string[];
  /** Registrable domains that belong to the brand (any sub-domain of them is official too). */
  official: string[];
  /** Top-level domains that belong to the brand (.bnpparibas). */
  officialTlds?: string[];
  /** Short or common names: only matched as a whole word next to a phishing word. */
  strict?: boolean;
  /** Pattern of the brand in a page title (accents removed, lower case). */
  title?: RegExp;
}

export const BRANDS: Brand[] = [
  { id: 'paypal', name: 'PayPal', keywords: ['paypal'], official: ['paypal.com', 'paypal.fr', 'paypal.me', 'paypalobjects.com'], title: /\bpaypal\b/ },
  { id: 'apple', name: 'Apple', keywords: ['apple', 'icloud', 'itunes'], official: ['apple.com', 'icloud.com', 'apple.fr', 'me.com', 'mzstatic.com'], title: /\b(apple|icloud|itunes)\b/ },
  {
    id: 'microsoft',
    name: 'Microsoft',
    keywords: ['microsoft', 'office365', 'outlook', 'onedrive', 'sharepoint', 'hotmail'],
    official: ['microsoft.com', 'live.com', 'outlook.com', 'outlook.fr', 'office.com', 'office365.com', 'office.net', 'microsoftonline.com', 'microsoft365.com', 'hotmail.com', 'hotmail.fr', 'live.fr', 'msn.com', 'onedrive.com', 'onedrive.live.com', 'sharepoint.com', 'bing.com', 'azure.com', 'windows.net', 'msftauth.net', 'msauth.net'],
    title: /\b(microsoft|office ?365|outlook|onedrive|sharepoint|hotmail)\b/,
  },
  { id: 'google', name: 'Google', keywords: ['google', 'gmail'], official: ['google.com', 'google.fr', 'gmail.com', 'youtube.com', 'googleusercontent.com', 'gstatic.com', 'googleapis.com', 'goo.gl', 'g.co', 'withgoogle.com', 'googlemail.com'], title: /\b(google|gmail)\b/ },
  { id: 'amazon', name: 'Amazon', keywords: ['amazon'], official: ['amazon.com', 'amazon.fr', 'amazon.de', 'amazon.co.uk', 'amazonaws.com', 'media-amazon.com', 'ssl-images-amazon.com', 'a2z.com', 'amazon.eu'], title: /\bamazon\b/ },
  { id: 'impots', name: 'impots.gouv.fr', keywords: ['impots', 'dgfip'], official: ['impots.gouv.fr', 'economie.gouv.fr', 'gouv.fr'], title: /\b(impots\.gouv|dgfip|finances publiques)\b/ },
  { id: 'ameli', name: 'Ameli (Assurance Maladie)', keywords: ['ameli'], official: ['ameli.fr', 'assurance-maladie.fr'], title: /\b(ameli|assurance maladie)\b/ },
  { id: 'laposte', name: 'La Poste', keywords: ['laposte'], official: ['laposte.fr', 'laposte.net', 'labanquepostale.fr', 'lapostegroupe.com'], title: /\bla poste\b/ },
  { id: 'colissimo', name: 'Colissimo', keywords: ['colissimo'], official: ['colissimo.fr', 'laposte.fr'], title: /\bcolissimo\b/ },
  { id: 'chronopost', name: 'Chronopost', keywords: ['chronopost'], official: ['chronopost.fr', 'chronopost.com'], title: /\bchronopost\b/ },
  { id: 'mondialrelay', name: 'Mondial Relay', keywords: ['mondialrelay'], official: ['mondialrelay.fr', 'mondialrelay.com'], title: /\bmondial relay\b/ },
  { id: 'dhl', name: 'DHL', keywords: ['dhl'], official: ['dhl.com', 'dhl.fr', 'dhl.de'], strict: true, title: /\bdhl\b/ },
  { id: 'creditagricole', name: 'Crédit Agricole', keywords: ['creditagricole'], official: ['credit-agricole.fr', 'credit-agricole.com', 'ca-paris.fr'], title: /\bcredit agricole\b/ },
  { id: 'bnpparibas', name: 'BNP Paribas', keywords: ['bnpparibas', 'bnp'], official: ['bnpparibas.com', 'bnpparibas.fr', 'bnpparibas.net'], officialTlds: ['bnpparibas'], title: /\bbnp( paribas)?\b/ },
  { id: 'societegenerale', name: 'Société Générale', keywords: ['societegenerale'], official: ['societegenerale.fr', 'societegenerale.com', 'sg.fr'], title: /\bsociete generale\b/ },
  { id: 'lcl', name: 'LCL', keywords: ['lcl'], official: ['lcl.fr', 'lcl.com'], strict: true, title: /\blcl\b/ },
  { id: 'caisseepargne', name: "Caisse d'Épargne", keywords: ['caisseepargne', 'caissedepargne'], official: ['caisse-epargne.fr'], title: /\bcaisse d.?epargne\b/ },
  { id: 'banquepopulaire', name: 'Banque Populaire', keywords: ['banquepopulaire'], official: ['banquepopulaire.fr'], title: /\bbanque populaire\b/ },
  { id: 'creditmutuel', name: 'Crédit Mutuel', keywords: ['creditmutuel'], official: ['creditmutuel.fr', 'creditmutuel.com'], title: /\bcredit mutuel\b/ },
  { id: 'cic', name: 'CIC', keywords: ['cic'], official: ['cic.fr'], strict: true, title: /\bcic\b/ },
  { id: 'labanquepostale', name: 'La Banque Postale', keywords: ['labanquepostale', 'banquepostale'], official: ['labanquepostale.fr', 'labanquepostale.com'], title: /\bla banque postale\b/ },
  { id: 'boursorama', name: 'BoursoBank', keywords: ['boursorama', 'boursobank'], official: ['boursorama.com', 'boursobank.com', 'boursorama-banque.com'], title: /\b(boursorama|boursobank)\b/ },
  { id: 'netflix', name: 'Netflix', keywords: ['netflix'], official: ['netflix.com', 'nflxext.com', 'nflximg.net'], title: /\bnetflix\b/ },
  { id: 'antai', name: 'ANTAI (amendes)', keywords: ['antai'], official: ['antai.gouv.fr', 'gouv.fr'], title: /\bantai\b/ },
  { id: 'franceconnect', name: 'FranceConnect', keywords: ['franceconnect'], official: ['franceconnect.gouv.fr', 'gouv.fr'], title: /\bfranceconnect\b/ },
  { id: 'caf', name: 'CAF', keywords: ['caf'], official: ['caf.fr'], strict: true, title: /\bcaf\b/ },
  { id: 'vinted', name: 'Vinted', keywords: ['vinted'], official: ['vinted.fr', 'vinted.com'], title: /\bvinted\b/ },
  { id: 'leboncoin', name: 'leboncoin', keywords: ['leboncoin'], official: ['leboncoin.fr'], title: /\bleboncoin\b/ },
  { id: 'docusign', name: 'DocuSign', keywords: ['docusign'], official: ['docusign.com', 'docusign.net'], title: /\bdocusign\b/ },
  { id: 'orange', name: 'Orange', keywords: ['orange'], official: ['orange.fr', 'orange.com', 'orange-business.com', 'sosh.fr'], strict: true },
  { id: 'sfr', name: 'SFR', keywords: ['sfr'], official: ['sfr.fr', 'sfr.com', 'red-by-sfr.fr'], strict: true, title: /\bsfr\b/ },
  { id: 'edf', name: 'EDF', keywords: ['edf'], official: ['edf.fr', 'edf.com'], strict: true, title: /\bedf\b/ },
  { id: 'facebook', name: 'Facebook', keywords: ['facebook'], official: ['facebook.com', 'fb.com', 'fbcdn.net', 'meta.com'], title: /\bfacebook\b/ },
  { id: 'instagram', name: 'Instagram', keywords: ['instagram'], official: ['instagram.com', 'cdninstagram.com'], title: /\binstagram\b/ },
  { id: 'whatsapp', name: 'WhatsApp', keywords: ['whatsapp'], official: ['whatsapp.com', 'whatsapp.net', 'wa.me'], title: /\bwhatsapp\b/ },
];

/** Words that, next to a brand name, make a host name look like a fake login or payment page. */
export const PHISHING_WORDS = new Set(
  'secure securite secur login signin logon verif verify verification account compte client clients connexion connect update maj support service services auth authentification banque bank paiement payment pay remboursement refund colis livraison suivi tracking facture invoice alerte alert confirm confirmation validation identifiant espace webmail wallet unlock recovery assistance aide help reactivation activation'.split(' '),
);

// Letters of other scripts that look like Latin ones (subset of Unicode TR39 confusables).
const CONFUSABLES: Record<string, string> = {
  а: 'a', е: 'e', о: 'o', р: 'p', с: 'c', у: 'y', х: 'x', і: 'i', ј: 'j', ѕ: 's', ԁ: 'd', һ: 'h', ӏ: 'l', ԛ: 'q', ԝ: 'w', ь: 'b', в: 'b', к: 'k', м: 'm', н: 'h', т: 't',
  ο: 'o', α: 'a', ν: 'v', ι: 'i', κ: 'k', ρ: 'p', τ: 't', υ: 'u', χ: 'x', ε: 'e', β: 'b', η: 'n', μ: 'u', ω: 'w',
  ɡ: 'g', ɑ: 'a', ʟ: 'l', ı: 'i', ȷ: 'j', ł: 'l', ø: 'o', đ: 'd', ħ: 'h',
};

/** Form of a label once look-alike characters are folded (both sides of a comparison use it). */
export function skeleton(s: string): string {
  let t = s.toLowerCase().normalize('NFKD').replace(/\p{M}/gu, '');
  t = [...t].map((c) => CONFUSABLES[c] ?? c).join('');
  return t.replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e').replace(/5/g, 's').replace(/\$/g, 's');
}

/** Optimal string alignment distance (Levenshtein plus adjacent transpositions). */
export function editDistance(a: string, b: string): number {
  const d: number[][] = Array.from({ length: a.length + 1 }, (_, i) => [i, ...new Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
    }
  }
  return d[a.length][b.length];
}

export function isOfficial(host: string, brand: Brand): boolean {
  const h = host.toLowerCase().replace(/\.$/, '');
  if (brand.official.some((o) => h === o || h.endsWith('.' + o))) return true;
  const tld = h.split('.').pop()!;
  if (brand.officialTlds?.includes(tld)) return true;
  // the brand's own name on another country code (google.de, amazon.it): not reported
  const sld = orgDomain(h).split('.')[0];
  return brand.keywords.includes(sld) && brand.official.some((o) => o.split('.')[0] === sld);
}

export type LookalikeKind = 'homoglyph' | 'typo' | 'subdomain' | 'word' | 'contains';

export interface Lookalike {
  host: string;
  /** Unicode form of the host, when it differs (punycode). */
  unicode?: string;
  brand: string;
  brandName: string;
  kind: LookalikeKind;
  /** The label or word that imitates the brand. */
  matched: string;
  /** Edit distance for a typo. */
  distance?: number;
  /** A phishing word sits next to the brand (login, compte, colis...). */
  phishingWord?: string;
  official: string[];
}

const KIND_RANK: Record<LookalikeKind, number> = { homoglyph: 0, typo: 1, subdomain: 2, word: 3, contains: 4 };

/** Brands imitated by a host name. One entry per brand, the strongest kind. */
export function findLookalikes(host: string): Lookalike[] {
  const h = host.toLowerCase().replace(/\.$/, '');
  if (net.isIP(h.replace(/^\[|\]$/g, ''))) return [];
  const unicode = domainToUnicode(h) || h;
  const org = orgDomain(h);
  const orgUnicode = domainToUnicode(org) || org;
  const sldRaw = org.split('.')[0];
  const sldUni = orgUnicode.split('.')[0];
  const sldSkel = skeleton(sldUni.replace(/-/g, ''));
  const subLabels = h.slice(0, Math.max(0, h.length - org.length)).replace(/\.$/, '').split('.').filter(Boolean);
  const uniSub = subLabels.map((l) => domainToUnicode(l) || l);
  // words of the host before the public suffix: labels split on hyphens
  const words = [...uniSub, sldUni].flatMap((l) => l.split('-')).filter(Boolean).map(skeleton);
  const phishingWord = words.find((w) => PHISHING_WORDS.has(w));
  const out: Lookalike[] = [];
  for (const brand of BRANDS) {
    if (isOfficial(h, brand)) continue;
    let best: Lookalike | undefined;
    const consider = (l: Lookalike) => {
      if (!best || KIND_RANK[l.kind] < KIND_RANK[best.kind]) best = l;
    };
    for (const kw of brand.keywords) {
      const k = skeleton(kw);
      const base = { host: h, unicode: unicode !== h ? unicode : undefined, brand: brand.id, brandName: brand.name, official: brand.official, phishingWord };
      const nonAscii = /[^\x00-\x7f]/.test(sldUni) || sldRaw.startsWith('xn--');
      const folded = sldUni.replace(/-/g, '') !== kw;
      if (sldSkel === k && folded && (nonAscii || /[0-9]|rn|vv/.test(sldUni))) {
        consider({ ...base, kind: 'homoglyph', matched: sldUni });
        continue;
      }
      if (sldUni === kw) continue; // brand name on an unlisted extension: left to the threat sources
      if (!brand.strict && k.length >= 5) {
        const dist = editDistance(sldSkel, k);
        const allowed = k.length >= 8 ? 2 : 1;
        // short names: substitutions and swaps only (amelie is not ameli)
        const lengthOk = k.length >= 8 || sldSkel.length === k.length;
        if (dist > 0 && dist <= allowed && lengthOk) consider({ ...base, kind: 'typo', matched: sldUni, distance: dist });
      }
      // brand as a whole label in front of an unrelated domain: paypal.com.verif-compte.ru
      const subIdx = uniSub.findIndex((l) => skeleton(l.replace(/-/g, '')) === k);
      if (subIdx >= 0 && (!brand.strict || phishingWord)) consider({ ...base, kind: 'subdomain', matched: uniSub[subIdx] });
      if (words.includes(k) && (!brand.strict || phishingWord)) consider({ ...base, kind: 'word', matched: words.find((w) => w === k)! });
      else if (!brand.strict && k.length >= 6 && sldSkel.includes(k) && sldSkel !== k) consider({ ...base, kind: 'contains', matched: sldUni });
    }
    if (best) out.push(best);
  }
  return out.sort((a, b) => KIND_RANK[a.kind] - KIND_RANK[b.kind]);
}

/** Brands a page title names. */
export function brandsInTitle(title: string): Brand[] {
  const t = title.toLowerCase().normalize('NFKD').replace(/\p{M}/gu, '').replace(/\s+/g, ' ');
  return BRANDS.filter((b) => b.title?.test(t));
}

/** A host made of an IDN label (xn--) whose Unicode form mixes scripts or folds onto ASCII. */
export function punycodeLabels(host: string): { label: string; unicode: string; mixedScripts: boolean }[] {
  return host
    .toLowerCase()
    .split('.')
    .filter((l) => l.startsWith('xn--'))
    .map((label) => {
      const unicode = domainToUnicode(label) || label;
      const latin = /\p{Script=Latin}/u.test(unicode);
      const other = /\p{Script=Cyrillic}|\p{Script=Greek}|\p{Script=Armenian}|\p{Script=Cherokee}/u.test(unicode);
      return { label, unicode, mixedScripts: latin && other };
    });
}
