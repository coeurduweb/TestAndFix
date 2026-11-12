// Sending server: reverse DNS (PTR, forward-confirmed), HELO name, TLS of the connection.
import net from 'node:net';
import { isPublicIp, reverseName } from '../../lib/net.js';
import { orgDomain } from '../received.js';
import type { NodeResolver, StepContext } from './types.js';
import { t } from '../../i18n.js';

async function lookup(resolver: NodeResolver, name: string, type: string): Promise<{ ok: string[]; code?: string }> {
  try {
    return { ok: ((await resolver(name, type)) as unknown[]).map((x) => String(x).toLowerCase().replace(/\.$/, '')) };
  } catch (e) {
    return { ok: [], code: (e as { code?: string }).code ?? 'ESERVFAIL' };
  }
}

async function addresses(resolver: NodeResolver, name: string): Promise<{ ips: string[]; nx: boolean; error: boolean }> {
  const [a, aaaa] = await Promise.all([lookup(resolver, name, 'A'), lookup(resolver, name, 'AAAA')]);
  // NXDOMAIN on either type means the name does not exist at all
  const nx = !a.ok.length && !aaaa.ok.length && (a.code === 'ENOTFOUND' || aaaa.code === 'ENOTFOUND');
  const error = [a.code, aaaa.code].some((c) => c && c !== 'ENOTFOUND' && c !== 'ENODATA');
  return { ips: [...a.ok, ...aaaa.ok], nx, error };
}

function normIp(ip: string): string {
  return net.isIPv6(ip) ? ip.toLowerCase() : ip;
}

/** Names that embed the IP or a dynamic-access keyword (typical of consumer lines). */
export function looksDynamic(name: string, ip?: string): boolean {
  const n = name.toLowerCase();
  if (/(^|[.-])(dyn|dynamic|dhcp|dsl|adsl|xdsl|pool|cable|ppp|pppoe|client|customer|cust|broadband|dial|dialup|static-ip|ip-\d)/.test(n)) return true;
  if (ip && net.isIPv4(ip)) {
    const o = ip.split('.');
    const fwd = o.join('[.-]');
    const rev = [...o].reverse().join('[.-]');
    if (new RegExp(`(^|\\D)(${fwd}|${rev})(\\D|$)`).test(n)) return true;
    if (o.slice(2).every((x) => n.includes(x)) && /\d+[-.]\d+[-.]\d+[-.]\d+/.test(n)) return true;
  }
  return false;
}

export async function runInfra(sc: StepContext) {
  const { facts, deps, c } = sc;
  const ip = facts.ip;
  const data: Record<string, unknown> = { ip, ipSource: facts.ipSource };
  sc.data.infrastructure = data;

  /* ---------------- reverse DNS ---------------- */
  let ptrs: string[] = [];
  let fcrdns: string | undefined;
  if (!ip) {
    c.missing('Reverse DNS', t("IP d'envoi inconnue"));
  } else if (!isPublicIp(ip)) {
    c.missing('Reverse DNS', t('{ip} est une adresse privée ou locale : pas de reverse DNS public à contrôler', { ip }));
    data.private = true;
  } else {
    const r = await lookup(deps.resolver, reverseName(ip), 'PTR');
    ptrs = r.ok;
    data.ptr = ptrs;
    data.ptrError = r.code && r.code !== 'ENOTFOUND' && r.code !== 'ENODATA' ? r.code : undefined;
    c.vars.ptr = ptrs[0];
    if (!ptrs.length && !data.ptrError) {
      const v6 = net.isIPv6(ip);
      c.add(v6 ? 'rdns.ipv6_missing' : 'rdns.missing', {
        evidence: `${reverseName(ip)} : ${r.code === 'ENOTFOUND' ? 'NXDOMAIN' : t('aucun PTR')}`,
        fallback: {
          title: v6 ? t("L'adresse IPv6 {ip} n'a pas de reverse DNS") : t("L'adresse {ip} n'a pas de reverse DNS"),
          why: t('Gmail et Yahoo exigent un reverse DNS (PTR) qui pointe vers un nom qui résout à son tour vers cette IP. Sans lui, les messages sont souvent refusés ou classés en spam.'),
          fix: [t("Demandez à l'hébergeur de l'IP {ip} de configurer un PTR vers le nom du serveur d'envoi (le même que le HELO).")],
          family: 'rdns',
          severity: v6 ? 'critical' : 'high',
          penalty: v6 ? 2 : 1.5,
        },
      });
    } else if (data.ptrError) {
      c.add('rdns.temperror', { evidence: `${reverseName(ip)} : ${data.ptrError}`, fallback: { title: t('Le reverse DNS de {ip} n’a pas pu être lu'), family: 'rdns', severity: 'low', penalty: 0.3 } });
    } else {
      const confirmed: string[] = [];
      let allNx = true;
      for (const p of ptrs.slice(0, 4)) {
        const fwd = await addresses(deps.resolver, p);
        if (!fwd.nx) allNx = false;
        if (fwd.ips.map(normIp).includes(normIp(ip))) confirmed.push(p);
      }
      fcrdns = confirmed[0];
      data.fcrdns = !!fcrdns;
      data.fcrdnsName = fcrdns;
      if (!fcrdns && allNx)
        c.add('rdns.ptr_target_nxdomain', {
          evidence: t("PTR : {ptr} ; ce nom n'existe pas dans le DNS", { ptr: ptrs.join(', ') }),
          fallback: { title: t('Le reverse DNS de {ip} pointe vers un nom qui n’existe pas ({ptr})'), family: 'rdns', severity: 'high', penalty: 1 },
        });
      else if (!fcrdns)
        c.add('rdns.fcrdns_mismatch', {
          evidence: t('PTR : {ptr} ; ces noms ne résolvent pas vers {ip}', { ptr: ptrs.join(', '), ip }),
          fallback: {
            title: t('Le reverse DNS de {ip} ({ptr}) ne revient pas vers {ip}'),
            why: t('Le nom inverse doit résoudre vers la même IP (FCrDNS). Gmail et Yahoo le vérifient.'),
            fix: [t('Ajoutez un enregistrement A (ou AAAA) {ptr} vers {ip}, ou changez le PTR pour un nom qui résout vers {ip}.')],
            family: 'rdns',
            severity: 'high',
            penalty: 1,
          },
        });
      else c.pass('rdns.fcrdns', 'rdns', t('Reverse DNS confirmé : {name}', { name: fcrdns }), ip);
      if (ptrs.length > 1)
        c.add('rdns.multiple_ptr', { vars: { value: ptrs.length }, evidence: ptrs.join(', '), fallback: { title: t("L'IP {ip} a plusieurs PTR"), family: 'rdns', severity: 'low', penalty: 0.1 } });
      if (looksDynamic(ptrs[0], ip))
        c.add('rdns.generic_dynamic', {
          evidence: ptrs[0],
          fallback: {
            title: t('Le reverse DNS {ptr} ressemble à une adresse grand public'),
            why: t('Un nom inverse générique (avec l’IP dedans, ou dyn, dsl, pool…) est typique des connexions résidentielles et pénalisé par les filtres.'),
            fix: [t("Demandez à l'hébergeur un PTR au nom du serveur d'envoi, par exemple mail.{domain}.")],
            family: 'rdns',
            severity: 'medium',
            penalty: 0.5,
          },
        });
    }
  }

  /* ---------------- HELO ---------------- */
  const helo = facts.helo;
  data.helo = helo;
  if (!helo) {
    if (facts.input.via === 'smtp') c.missing('HELO', t('Le client ne s’est pas annoncé'));
    else c.missing('HELO', t('Nom HELO introuvable dans les Received du message'));
  } else {
    const h = helo.toLowerCase();
    const literal = /^\[.*\]$/.test(h);
    const bareIp = !literal && (net.isIP(h) > 0 || /^[\d.]+$/.test(h));
    const heloData: Record<string, unknown> = { name: helo, literal, bareIp };
    data.heloCheck = heloData;
    if (/^(localhost|localhost\.localdomain|127\.0\.0\.1|\[127\.0\.0\.1\]|::1|\[ipv6:::1\])$/i.test(h))
      c.add('helo.localhost', { fallback: { title: t('Le serveur s’annonce comme {helo}'), family: 'helo', severity: 'high', penalty: 1 } });
    else if (bareIp) c.add('helo.ip_unbracketed', { fallback: { title: t('HELO {helo} : adresse IP sans crochets'), family: 'helo', severity: 'medium', penalty: 0.5 } });
    else if (literal) c.add('helo.address_literal', { fallback: { title: t('HELO {helo} : adresse IP au lieu d’un nom'), family: 'helo', severity: 'low', penalty: 0.3 } });
    else if (!h.includes('.')) c.add('helo.not_fqdn', { fallback: { title: t('HELO {helo} : pas un nom de domaine complet'), family: 'helo', severity: 'medium', penalty: 0.5 } });
    else {
      if (/[^a-z0-9.-]|^-|-\.|\.-|\.\./.test(h))
        c.add('helo.invalid_characters', { fallback: { title: t('HELO {helo} : caractères invalides'), family: 'helo', severity: 'low', penalty: 0.3 } });
      if (/(^|\.)(example\.(com|net|org)|localdomain|local|lan|home|internal|invalid|test)$/.test(h))
        c.add('helo.default_template', { fallback: { title: t('HELO {helo} : nom par défaut ou interne'), family: 'helo', severity: 'medium', penalty: 0.5 } });
      const heloOrg = orgDomain(h);
      const ownOrg = orgDomain(deps.config.mail.domain);
      const bigOrgs = ['gmail.com', 'google.com', 'outlook.com', 'yahoo.com', 'hotmail.com', 'live.com', 'microsoft.com', 'apple.com', 'icloud.com'];
      const ptrOrg = orgDomain(ptrs[0]);
      if (heloOrg && ((ownOrg && heloOrg === ownOrg) || (bigOrgs.includes(heloOrg) && ptrOrg !== heloOrg && ip && isPublicIp(ip))))
        c.add('helo.impersonation', { fallback: { title: t('HELO {helo} : nom d’un autre domaine'), family: 'helo', severity: 'high', penalty: 1.5 } });
      if (ip && isPublicIp(ip)) {
        const fwd = await addresses(deps.resolver, h);
        heloData.addresses = fwd.ips;
        if (fwd.nx) c.add('helo.not_resolving', { evidence: `${h} : NXDOMAIN`, fallback: { title: t('HELO {helo} : ce nom n’existe pas dans le DNS'), family: 'helo', severity: 'low', penalty: 0.3 } });
        else if (!fwd.error && !fwd.ips.map(normIp).includes(normIp(ip)))
          c.add('helo.ip_mismatch', {
            evidence: t("{name} → {addresses} ; IP d'envoi {ip}", { name: h, addresses: fwd.ips.join(', ') || t('aucune adresse'), ip }),
            fallback: { title: t('HELO {helo} ne résout pas vers {ip}'), family: 'helo', severity: 'low', penalty: 0.3 },
          });
        else if (!fwd.error) c.pass('helo.resolves', 'helo', t('HELO {helo} résout vers {ip}', { helo, ip }));
      }
      if (ptrs.length && !ptrs.includes(h))
        c.add('helo.ptr_mismatch', { evidence: `HELO ${h} / PTR ${ptrs.join(', ')}`, fallback: { title: t('HELO {helo} différent du reverse DNS {ptr}'), family: 'helo', severity: 'info', penalty: 0.1 } });
      if (looksDynamic(h, ip)) c.add('helo.dynamic_name', { fallback: { title: t('HELO {helo} : nom d’accès grand public'), family: 'helo', severity: 'medium', penalty: 0.5 } });
    }
  }

  /* ---------------- TLS ---------------- */
  const tls = facts.tls;
  data.tls = tls;
  if (!tls || tls.used === null) {
    c.missing('TLS', tls?.source === 'relay' ? t("Le relais n'a pas écrit de Received : le chiffrement de la connexion d'origine est inconnu") : facts.input.via === 'smtp' ? t('Session SMTP inconnue') : t('Le Received du premier relais ne dit pas si TLS a été utilisé'));
  } else if (!tls.used) {
    c.add('tls.inbound_plaintext', { fallback: { title: t('Le message est arrivé sans chiffrement TLS'), family: 'tls', severity: 'high', penalty: 1 } });
  } else {
    const proto = tls.protocol ?? '';
    if (/^(SSLv3|TLSv1(\.0|\.1)?)$/i.test(proto))
      c.add('tls.inbound_old_version', { vars: { value: proto }, fallback: { title: t('Le message est arrivé en {value}, version obsolète'), family: 'tls', severity: 'medium', penalty: 0.5 } });
    else if (tls.cipher && /RC4|3DES|DES-CBC|NULL|EXPORT|anon/i.test(tls.cipher))
      c.add('tls.inbound_weak_cipher', { vars: { value: tls.cipher }, fallback: { title: t('Chiffrement faible : {value}'), family: 'tls', severity: 'low', penalty: 0.3 } });
    else c.pass('tls.inbound', 'tls', proto ? t('Reçu en TLS ({detail})', { detail: `${proto}${tls.cipher ? `, ${tls.cipher}` : ''}` }) : t('Reçu en TLS'));
  }
  /* ---------------- sender domains ---------------- */
  const domainState = async (d: string) => {
    let mx: { exchange?: string }[] = [];
    let nx = false;
    try {
      mx = (await deps.resolver(d, 'MX')) as { exchange?: string }[];
    } catch (e) {
      nx = (e as { code?: string }).code === 'ENOTFOUND';
    }
    const nullMx = mx.length > 0 && mx.every((m) => !m.exchange || m.exchange === '.' || m.exchange === '');
    const addr = !mx.length && !nx ? await addresses(deps.resolver, d) : { ips: [] as string[], nx, error: false };
    return { nx: nx || addr.nx, nullMx, canReceive: (mx.length > 0 && !nullMx) || addr.ips.length > 0, error: addr.error };
  };
  const fromDomain = facts.fromDomain;
  if (fromDomain) {
    const st = await domainState(fromDomain);
    data.fromDomain = { domain: fromDomain, ...st };
    if (st.nx || (!st.canReceive && !st.nullMx && !st.error))
      c.add('reputation.from_domain_not_resolvable', {
        evidence: st.nx ? `${fromDomain} : NXDOMAIN` : t('{domain} : ni MX ni adresse', { domain: fromDomain }),
        fallback: { title: t('Le domaine {domain} ne peut pas recevoir de réponse'), family: 'reputation', severity: 'critical', penalty: 2 },
      });
    if (st.nullMx) c.add('mx.null_mx_on_sending_domain', { evidence: `${fromDomain} MX 0 .`, fallback: { title: t('{domain} déclare ne recevoir aucun e-mail (MX nul)'), family: 'mx', severity: 'high', penalty: 1.5 } });
  }
  const env = facts.envelopeDomain;
  if (env && fromDomain && env !== fromDomain && facts.envelopeFrom) {
    const st = await domainState(env);
    if (st.nullMx) c.add('mx.null_mx_on_sending_domain', { evidence: `${env} MX 0 .`, fallback: { title: t('{envelope_domain} déclare ne recevoir aucun e-mail (MX nul)'), family: 'mx', severity: 'high', penalty: 1.5 } });
    else if (!st.canReceive && !st.error)
      c.add('mx.envelope_domain_cannot_receive', { evidence: t('{domain} : ni MX ni adresse', { domain: env }), fallback: { title: t('Les retours vers {envelope_domain} ne peuvent pas arriver'), family: 'mx', severity: 'medium', penalty: 0.5 } });
  }
  const local = (facts.envelopeFrom ?? '').split('@')[0];
  if (facts.headers.some((h) => h.key === 'x-php-originating-script') || ['www-data', 'apache', 'nobody', 'nginx', 'php'].includes(local))
    c.add('infrastructure.web_server_mail', { evidence: facts.envelopeFrom, fallback: { title: t('Le message part directement du serveur web'), family: 'infrastructure', severity: 'medium', penalty: 0.5 } });
  const fromLocal = (facts.fromAddress ?? '').split('@')[0];
  if (/^(no[-_.]?reply|ne[-_.]?pas[-_.]?repondre|donotreply|do[-_.]not[-_.]reply)$/i.test(fromLocal) && !facts.headers.some((h) => h.key === 'reply-to'))
    c.add('reputation.noreply_sender', { evidence: facts.fromAddress, fallback: { title: t('Adresse d’expédition « noreply »'), family: 'reputation', severity: 'low', penalty: 0.2 } });
  if (facts.isBulk) {
    if (!facts.headers.some((h) => h.key === 'feedback-id'))
      c.add('reputation.feedback_id_missing', { fallback: { title: t('Pas d’en-tête Feedback-ID'), family: 'reputation', severity: 'low', penalty: 0.1 } });
    c.add('reputation.postmaster_tools_suggested', { fallback: { title: t('Suivez la réputation de {domain} dans Google Postmaster Tools'), family: 'reputation', severity: 'info', penalty: 0 } });
  }
  return { ptrs, fcrdns };
}
