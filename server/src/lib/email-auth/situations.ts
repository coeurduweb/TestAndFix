// Fallback texts for the situation ids these analyzers emit and that knowledge/situations/ does
// not hold yet. explain() uses them only when the base has no entry with that id: once an entry
// is added to the base, the base wins. Keep in French, vouvoiement, no em or en dash.
import type { Severity } from '../../knowledge/engine.js';
import { msg } from '../../i18n.js';

export interface FallbackText {
  title: string;
  why?: string;
  fix?: string[];
  family?: string;
  severity?: Severity;
  penalty?: number;
}

export const FALLBACKS: Record<string, FallbackText> = {
  // --- SPF
  'spf.domain_nxdomain': {
    family: 'spf', severity: 'critical', penalty: 2,
    title: msg('Le domaine {domain} n’existe pas dans le DNS'),
    why: msg('Le DNS répond que ce nom n’existe pas : aucun SPF ne peut y être lu et les messages envoyés avec ce domaine seront refusés.'),
    fix: [msg('Vérifiez l’orthographe du domaine.'), msg('Si le domaine vient d’être acheté, vérifiez chez le registrar qu’il est bien délégué à vos serveurs DNS.')],
  },
  'spf.unknown_modifier': {
    family: 'spf', severity: 'info', penalty: 0,
    title: msg('Modificateur inconnu dans le SPF : {value}'),
    why: msg('Les destinataires ignorent les modificateurs qu’ils ne connaissent pas (RFC 7208 §6) : celui-ci n’a aucun effet.'),
    fix: [msg('Retirez {value} s’il s’agit d’une faute de frappe ou d’un reste d’ancienne configuration.')],
  },
  'spf.permerror': {
    family: 'spf', severity: 'high', penalty: 1.5,
    title: msg('Le SPF de {domain} est en erreur permanente'),
    why: msg('L’évaluation s’arrête sur une erreur ({value}) : les destinataires traitent le message comme sans SPF valide, et DMARC ne peut pas s’appuyer sur SPF.'),
    fix: [msg('Ouvrez le vérificateur SPF sur {domain} : il indique le terme en cause et propose un enregistrement corrigé.')],
  },
  'spf.eval_neutral': {
    family: 'spf', severity: 'medium', penalty: 0.5,
    title: msg('L’IP {ip} n’est ni autorisée ni refusée par le SPF de {domain}'),
    why: msg('Aucun mécanisme ne correspond à cette IP ({value}) : le résultat est neutral, qui ne compte pas comme un SPF réussi pour DMARC.'),
    fix: [msg('Si {ip} envoie légitimement pour {domain}, ajoutez ip4:{ip} (ou l’include: de son fournisseur) avant le all.'), msg('Terminez le SPF par ~all ou -all.')],
  },

  // --- DKIM
  'dkim.key_service_type': {
    family: 'dkim', severity: 'high', penalty: 1.5,
    title: msg('La clé DKIM {selector} n’est pas utilisable pour l’e-mail'),
    why: msg('La balise s={value} limite la clé à d’autres services : les destinataires doivent ignorer cette clé pour les e-mails (RFC 6376 §3.6.1).'),
    fix: [msg('Retirez la balise s= ou écrivez s=email dans l’enregistrement {selector}._domainkey.{domain}.')],
  },
  'dkim.selector_not_discovered': {
    family: 'dkim', severity: 'low', penalty: 0,
    title: msg('Aucune clé DKIM trouvée parmi {value} sélecteurs courants'),
    why: msg('Cela ne prouve pas l’absence de DKIM : beaucoup de services utilisent un sélecteur propre au compte, impossible à deviner.'),
    fix: [msg('Ouvrez l’en-tête DKIM-Signature d’un message envoyé par {domain} : la balise s= donne le sélecteur, saisissez-le ici.'), msg('Si aucun message n’est signé, activez DKIM dans l’outil d’envoi et publiez la clé qu’il fournit.')],
  },
  'dkim.wildcard': {
    family: 'dkim', severity: 'info', penalty: 0,
    title: msg('Le DNS de {domain} répond à n’importe quel sélecteur DKIM'),
    why: msg('Un enregistrement générique (*) répond même pour un sélecteur inventé : les clés listées ici peuvent en être des copies et non de vraies clés.'),
    fix: [msg('Retirez l’enregistrement générique sous _domainkey.{domain} et publiez chaque sélecteur séparément.')],
  },

  // --- DMARC
  'dmarc.duplicate_tag': {
    family: 'dmarc', severity: 'medium', penalty: 0.5,
    title: msg('La balise {value} apparaît deux fois dans le DMARC de {domain}'),
    why: msg('Une balise répétée rend l’enregistrement ambigu : selon le destinataire, la première valeur, la dernière, ou aucune est retenue.'),
    fix: [msg('Gardez une seule occurrence de {value} dans l’enregistrement _dmarc.{domain}.')],
  },
  'dmarc.inherited': {
    family: 'dmarc', severity: 'info', penalty: 0,
    title: msg('{domain} applique la politique DMARC de {value}'),
    why: msg('Aucun enregistrement sur _dmarc.{domain} : les destinataires lisent celui du domaine organisationnel {value} et appliquent sa balise sp= (ou p= à défaut).'),
    fix: [msg('Rien à faire si cette politique convient. Pour une politique propre à {domain}, publiez un TXT sur _dmarc.{domain}.')],
  },
  'dmarc.invalid_tag_value': {
    family: 'dmarc', severity: 'low', penalty: 0.3,
    title: msg('Valeur invalide dans le DMARC de {domain}'),
    why: msg('La valeur {value} n’est pas reconnue : les destinataires ignorent la balise ou appliquent sa valeur par défaut.'),
    fix: [msg('Corrigez la balise dans l’enregistrement _dmarc.{domain} selon l’explication affichée.')],
  },
  'dmarc.strict_alignment': {
    family: 'dmarc', severity: 'info', penalty: 0,
    title: msg('Alignement strict demandé ({value})'),
    why: msg('Avec un alignement strict, un message signé ou envoyé avec un sous-domaine de {domain} (par exemple par un outil d’envoi) échoue à DMARC.'),
    fix: [msg('Gardez le strict seulement si tous vos envois utilisent exactement {domain} ; sinon retirez adkim=s et aspf=s.')],
  },

  // --- BIMI
  'bimi.missing_dmarc_not_enforced': {
    family: 'bimi', severity: 'info', penalty: 0,
    title: msg('Pas de BIMI pour {domain}, et DMARC ne le permettrait pas encore'),
    why: msg('BIMI n’affiche un logo que si DMARC est en quarantine (pct=100) ou reject. Aujourd’hui : {value}. Publier BIMI maintenant ne servirait à rien.'),
    fix: [msg('Passez d’abord DMARC en p=quarantine puis p=reject (voir la section DMARC).'), msg('Ensuite seulement, publiez default._bimi.{domain} avec votre logo SVG Tiny PS.')],
  },
  'bimi.svg_recommendation': {
    family: 'bimi', severity: 'info', penalty: 0,
    title: msg('Le logo BIMI de {domain} peut être amélioré'),
    why: msg('Ces points ne bloquent pas l’affichage mais sont recommandés par le profil SVG Tiny PS ou par Google : {value}.'),
    fix: [msg('Ajoutez un élément <desc> décrivant le logo et gardez un <title> court (64 caractères au plus), puis republiez le fichier.')],
  },

  // --- DNSSEC
  'dnssec.ds_missing': {
    family: 'dnssec', severity: 'low', penalty: 0.2,
    title: msg('La zone {domain} est signée mais le registre n’a pas d’enregistrement DS'),
    why: msg('Les clés DNSSEC sont publiées, mais sans DS chez le registre la chaîne de confiance n’existe pas : aucun résolveur ne valide la zone.'),
    fix: [msg('Dans votre hébergeur DNS, copiez l’enregistrement DS (ou la clé KSK) de {domain}.'), msg('Ajoutez-le chez le registrar du domaine, rubrique DNSSEC.')],
  },
  'dnssec.ds_sha1': {
    family: 'dnssec', severity: 'low', penalty: 0.1,
    title: msg('Le DS de {domain} n’utilise que SHA-1'),
    why: msg('Le condensé SHA-1 (type 1) n’est plus recommandé pour les DS (RFC 8624 §3.3) ; certains validateurs pourraient cesser de l’accepter.'),
    fix: [msg('Publiez chez le registrar un DS de type 2 (SHA-256) pour la même clé, puis retirez celui de type 1.')],
  },

  // --- MX / SMTP
  'mx.some_target_without_address': {
    family: 'mx', severity: 'medium', penalty: 0.5,
    title: msg('Un MX de {domain} n’a pas d’adresse IP'),
    why: msg('Le serveur {value} est annoncé comme MX mais son nom ne donne aucune adresse : les expéditeurs perdent du temps à l’essayer avant de passer au suivant.'),
    fix: [msg('Retirez {value} de la liste des MX de {domain}, ou créez son enregistrement A.')],
  },
  'mx.host_unreachable': {
    family: 'mx', severity: 'medium', penalty: 0.5,
    title: msg('Le MX {value} ne répond pas sur le port 25'),
    why: msg('Les autres MX répondent, mais celui-ci non : les expéditeurs qui tombent dessus retardent leurs envois.'),
    fix: [msg('Vérifiez que le service SMTP de {value} fonctionne et que le port 25 est ouvert dans son pare-feu.'), msg('Sinon, retirez-le des MX de {domain}.')],
  },

  // --- infrastructure (zone, registrar)
  'infrastructure.ns_single': {
    family: 'infrastructure', severity: 'high', penalty: 1,
    title: msg('{domain} n’a qu’un serveur de noms'),
    why: msg('Si ce serveur tombe, plus aucun nom de {domain} ne répond : site, mails et MX disparaissent ensemble. La RFC 1034 §4.1 demande au moins deux serveurs.'),
    fix: [msg('Ajoutez un second serveur de noms chez votre hébergeur DNS, puis déclarez-le chez le registrar.')],
  },
  'infrastructure.ns_unresolvable': {
    family: 'infrastructure', severity: 'high', penalty: 1,
    title: msg('Un serveur de noms de {domain} n’a pas d’adresse'),
    why: msg('Le serveur {value} est délégué mais son nom ne donne aucune adresse IP : les résolveurs ne peuvent pas l’interroger.'),
    fix: [msg('Corrigez le nom du serveur chez le registrar, ou créez son enregistrement A (glue) s’il est dans la zone.')],
  },
  'infrastructure.ns_same_network': {
    family: 'infrastructure', severity: 'low', penalty: 0.2,
    title: msg('Tous les serveurs de noms de {domain} sont dans le même réseau'),
    why: msg('Ils partagent le réseau {value} : une panne de ce réseau coupe tous les serveurs à la fois. Ce contrôle regarde les plages /24 des adresses.'),
    fix: [msg('Ajoutez un serveur de noms hébergé sur un autre réseau, ou un service DNS secondaire.')],
  },
  'infrastructure.ns_parent_child_mismatch': {
    family: 'infrastructure', severity: 'medium', penalty: 0.5,
    title: msg('Les serveurs de noms déclarés chez le registre et dans la zone diffèrent'),
    why: msg('Le registre et la zone {domain} ne listent pas les mêmes serveurs : certains résolveurs suivent une liste, d’autres l’autre, et les réponses peuvent varier.'),
    fix: [msg('Alignez la liste NS de la zone et celle déclarée chez le registrar.')],
  },
  'infrastructure.soa_serial_mismatch': {
    family: 'infrastructure', severity: 'medium', penalty: 0.5,
    title: msg('Les serveurs de {domain} n’ont pas la même version de la zone'),
    why: msg('Les serial SOA diffèrent ({value}) : un serveur n’a pas reçu la dernière modification, et les résolveurs obtiennent des réponses différentes selon le serveur interrogé.'),
    fix: [msg('Forcez la synchronisation (transfert de zone) chez votre hébergeur DNS.'), msg('Si la zone vient d’être modifiée, relancez le contrôle dans quelques minutes.')],
  },
  'infrastructure.soa_missing': {
    family: 'infrastructure', severity: 'high', penalty: 1,
    title: msg('Aucun SOA lisible pour {domain}'),
    why: msg('Aucun serveur n’a renvoyé l’enregistrement SOA de la zone : la zone est peut-être mal servie.'),
    fix: [msg('Vérifiez chez votre hébergeur DNS que la zone {domain} existe et est publiée sur chaque serveur.')],
  },
  'infrastructure.caa_missing': {
    family: 'infrastructure', severity: 'info', penalty: 0,
    title: msg('Aucun enregistrement CAA pour {domain}'),
    why: msg('Sans CAA, toute autorité de certification peut émettre un certificat pour {domain} (RFC 8659). Ce n’est pas une erreur, c’est une protection en moins.'),
    fix: [msg('Publiez un CAA qui nomme l’autorité que vous utilisez, par exemple 0 issue "letsencrypt.org".')],
  },
  'infrastructure.caa_unknown_critical': {
    family: 'infrastructure', severity: 'medium', penalty: 0.5,
    title: msg('CAA critique inconnu sur {domain}'),
    why: msg('Une balise {value} marquée critique (flag 128) et inconnue interdit toute émission de certificat (RFC 8659 §4.1).'),
    fix: [msg('Retirez le flag 128 de la balise {value} ou supprimez-la.')],
  },
  'infrastructure.domain_expired': {
    family: 'infrastructure', severity: 'critical', penalty: 3,
    title: msg('Le domaine {domain} a expiré'),
    why: msg('La date d’expiration ({value}) est dépassée : le registre peut suspendre le domaine à tout moment, et tout s’arrête alors (site, mails).'),
    fix: [msg('Renouvelez {domain} chez votre registrar immédiatement.')],
  },
  'infrastructure.domain_hold': {
    family: 'infrastructure', severity: 'critical', penalty: 3,
    title: msg('Le domaine {domain} est suspendu (hold)'),
    why: msg('Le statut {value} retire le domaine du DNS : aucun nom de {domain} ne répond.'),
    fix: [msg('Contactez votre registrar : ce statut suit souvent un impayé, une vérification de coordonnées non faite ou une plainte.')],
  },
  'infrastructure.domain_pending_delete': {
    family: 'infrastructure', severity: 'critical', penalty: 3,
    title: msg('Le domaine {domain} est en cours de suppression'),
    why: msg('Le statut {value} indique que le domaine va être supprimé puis remis en vente.'),
    fix: [msg('Contactez votre registrar sans attendre : une restauration est parfois possible pendant la période de rédemption.')],
  },
  'infrastructure.domain_not_registered': {
    family: 'infrastructure', severity: 'critical', penalty: 3,
    title: msg('Le domaine {domain} n’est pas enregistré'),
    why: msg('Le registre ne connaît pas ce domaine : il n’existe pas, ou il a été supprimé.'),
    fix: [msg('Vérifiez l’orthographe ; si le domaine vous appartenait, contactez votre registrar.')],
  },

  // --- blocklists
  'blacklist.listed': {
    family: 'blacklist', severity: 'medium', penalty: 0.5,
    title: msg('{value} est inscrit sur {list_name}'),
    why: msg('Des destinataires consultent cette liste avant d’accepter un message : une inscription peut faire classer en spam ou refuser les envois.'),
    fix: [msg('Trouvez la cause (compte piraté, formulaire abusé, envoi sans consentement) et corrigez-la.'), msg('Demandez le retrait : {delist_url}')],
  },
};
