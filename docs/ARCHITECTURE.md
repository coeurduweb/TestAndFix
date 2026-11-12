# Architecture de check

En bref : une application Node/TypeScript (API + interface React servie par le même processus), un
serveur SMTP intégré qui reçoit les mails de test, un lecteur IMAP en repli, SpamAssassin dans un
conteneur voisin, une base SQLite purgée à 90 jours. Toutes les requêtes DNS partent des serveurs
racine (résolution itérative maison) : aucun cache réseau entre l'outil et la vérité.

## Composants

| Composant | Rôle | Où |
|---|---|---|
| API HTTP | Fastify 5, routes `/api/*`, flux SSE pour les résultats en direct | `server/src/` |
| Interface | React 19 + Vite, servie en statique par l'API en production | `web/` |
| Résolution DNS | client UDP/TCP (`dns/client.ts`) + résolution itérative depuis la racine (`dns/iterative.ts`) | `server/src/dns/` |
| Réception SMTP | `smtp-server`, accepte seulement les adresses de tests actifs | `server/src/mail/smtp.ts` |
| Réception IMAP | `imapflow` en IDLE sur une boîte attrape-tout | `server/src/mail/imap.ts` |
| Analyse d'un mail | `mailauth` (SPF, DKIM, DMARC, ARC, BIMI) branché sur notre résolveur, SpamAssassin (`spamd`), DNSBL, contenu, liens | `server/src/mail/analyze/` |
| Base de situations | `knowledge/situations/*.yaml`, chargée au démarrage, moteur de règles + gabarits | `server/src/knowledge/` |
| Outils | un dossier par outil, découvert automatiquement au démarrage | `server/src/tools/<id>/`, `web/src/tools/<id>/` |
| Stockage | SQLite (`better-sqlite3`), une table par type de résultat, purge quotidienne > 90 jours | `server/src/db.ts` |
| Purge des caches | agent hôte `agent/check-agent.py` + `agent/flush-caches.sh` | `agent/` |

## Règle « sans cache »

1. Toute résolution passe par `ResolveSession` : elle part des 13 serveurs racine, suit les
   délégations, interroge les serveurs autoritaires avec RD=0. Une session vit le temps d'une seule
   action (un scan, une analyse) ; elle ne mémorise que les délégations de cette action, pour ne pas
   refaire la descente depuis la racine à chaque sélecteur DKIM. Rien n'est réutilisé d'une action à
   l'autre.
2. La propagation interroge les résolveurs publics (ils répondent avec leur propre cache : c'est ce
   qu'on mesure) et les serveurs autoritaires en référence ; chaque résultat dit si le résolveur est
   à jour et combien de secondes de TTL il lui reste.
3. Les réponses HTTP de l'API portent `Cache-Control: no-store`. Aucune réponse n'est mise en cache
   côté serveur.
4. SpamAssassin a besoin d'un résolveur récursif pour ses tests réseau : un Unbound dédié, cache à
   TTL 0, uniquement pour lui.

## Contrat d'un outil

Serveur, `server/src/tools/<id>/index.ts` :

```ts
export const tool: ServerTool = {
  id: 'spf',
  public: false,               // true pour les générateurs
  register(app, ctx) { app.post('/api/spf/check', ...) },
};
```

Interface, `web/src/tools/<id>/index.tsx` :

```ts
export const tool: WebTool = {
  id: 'spf', group: 'domaine', title: 'SPF', path: '/spf',
  detect: (input) => ...,      // score 0..1 pour la saisie universelle
  Page: lazy(() => import('./Page')),
};
```

Les deux registres se construisent seuls (lecture du dossier côté serveur, `import.meta.glob` côté
interface) : ajouter un outil ne modifie aucun fichier partagé.

## Sécurité

- Mot de passe unique (`TESTANDFIX_PASSWORD_HASH`, scrypt), cookie de session signé, HttpOnly, SameSite=Lax,
  30 jours. Limitation des tentatives de connexion. Les routes `public: true` restent ouvertes.
- Les requêtes sortantes vers des URL fournies par l'utilisateur (liens, BIMI) refusent les adresses
  privées et locales (protection SSRF), limitent taille et durée.
- L'agent de purge n'exécute qu'un script fixe, via une règle sudoers limitée à ce script.
- **Un carnet par navigateur** (décision du 2026-11-11, `server/src/owner.ts`, `server/src/me.ts`) : le
  mot de passe étant partagé, chaque navigateur connecté reçoit un secret aléatoire de 256 bits dans le
  cookie `check_device` (HttpOnly, Secure en HTTPS, SameSite=Lax, 400 jours) ; le serveur n'en garde que
  le SHA-256 (`devices`), rattaché à un carnet (`owners`). Le carnet n'est créé qu'à la connexion,
  par `GET /api/auth/status` ou `GET /api/me`. Toute donnée personnelle (`results`, `mail_addresses`,
  `mail_messages`, `dmarc_reports`, `shares`) porte `owner_id` et chaque route filtre dessus ; l'id
  d'un autre carnet répond exactement comme un id inexistant. Refusé, ne pas y revenir : l'empreinte
  technique de l'appareil et l'adresse IP (voir Sprint 10 du backlog).
- Relier un appareil : code de 8 caractères, 5 minutes, usage unique, haché ; l'aperçu montre les
  appareils du carnet visé avant toute liaison, et verser les données d'un navigateur exige un second
  choix explicite (`confirmMerge`). Échecs limités à 5 par IP et 60 pour tout le serveur, par minute.
  Détacher un appareil ferme ses flux en direct, supprime les codes du carnet et les liens de partage
  qu'il avait créés ; le dernier appareil détaché efface les données.
- IP cliente : `trustProxy` ne fait confiance qu'au pair direct privé ou local (Nginx), donc l'IP
  retenue est celle que Nginx ajoute en dernier dans X-Forwarded-For, pas une valeur fournie par le client.
- Requêtes d'écriture sous `/api/` refusées si elles viennent d'un autre site (`Sec-Fetch-Site`,
  `Origin`) ; `X-Frame-Options: SAMEORIGIN` et `frame-ancestors 'self'` sur toutes les réponses.
- Journaux de l'application : méthode, motif de route, statut et durée seulement ; jamais l'URL réelle,
  la requête, les cookies ni le message d'une erreur (qui peut contenir un domaine). Les journaux
  d'accès de Nginx sur l'hôte gardent encore les URL complètes (voir docs/DEPLOIEMENT.md).

## Données

Conservation 90 jours (`TESTANDFIX_RETENTION_DAYS`), purge au démarrage puis toutes les 24 h. Un mail de
test conserve le message brut (.eml) pour pouvoir relancer l'analyse. Les lignes antérieures au
carnet (owner_id NULL) ne sont visibles de personne et partent avec cette purge. La purge retire aussi
les appareils non revus pendant la durée de conservation, les carnets sans appareil avec leurs données,
les carnets vides non revus depuis 7 jours, les codes de liaison expirés et les partages orphelins.
Un partage (`/partage/<jeton>`) ne concerne qu'un rapport de mail, reste derrière le mot de passe et
masque l'adresse de test du propriétaire.

## Sauvegardes, autotest de réception, IMAP chiffré (2026-11-11)

- **Sauvegarde quotidienne** (US-098, `server/src/backup.ts`) : l'application copie elle-même la base
  avec `db.backup()` de better-sqlite3 (copie en ligne, cohérente, pendant que l'application écrit),
  sans crontab sur l'hôte. Fichiers `check-AAAA-MM-JJ.sqlite` (date UTC) dans `TESTANDFIX_BACKUP_DIR`
  (par défaut `<TESTANDFIX_DATA_DIR>/backups`, en production `/data/backups` dans le volume `check-data`),
  écrits sous un nom temporaire puis renommés, mode 600. Première copie 5 minutes après le démarrage
  puis toutes les 24 h, jamais deux à la fois ; on garde les `TESTANDFIX_BACKUP_KEEP` plus récentes
  (14 par défaut, 0 coupe les sauvegardes). Un échec est journalisé avec son seul code (`ENOSPC`…),
  jamais le chemin ni le message, et n'arrête rien. Les copies contiennent les données des carnets :
  elles suivent les mêmes règles que la base (même volume, même accès).
- **Autotest de réception** (US-099, `server/src/mail/selftest.ts`) : si `TESTANDFIX_SELFTEST_SMTP_HOST`
  est renseigné, l'application s'envoie un petit message toutes les `TESTANDFIX_SELFTEST_INTERVAL_HOURS`
  (6 par défaut, premier envoi une minute après le démarrage) par le chemin des vrais expéditeurs :
  le domaine public des adresses de test, port 25, donc le relais de l'hôte quand il y en a un, puis
  retour dans le conteneur. STARTTLS si le serveur le propose, certificat non vérifié (celui de Postfix est
  autosigné), expéditeur vide (`MAIL FROM:<>`) pour qu'une copie tardive ne rebondisse vers personne.
  Le nom est résolu depuis la racine comme toute requête DNS de l'outil. L'adresse de test n'a pas
  de carnet (`owner_id` NULL, libellé réservé) : aucune route ne la voit, son message est enregistré
  (l'écriture fait partie du test) mais n'est ni analysé ni annoncé, et les deux lignes sont
  supprimées dès la fin du contrôle (et au début du suivant, après un arrêt brutal). Le résultat
  (heure, réussite, durée, code court comme `smtp_550`, `not_received`, `ECONNECTION`) est gardé
  dans `settings` et survit à un redémarrage.
- **`GET /api/health/reception`** (public, pour une sonde externe) : `200 {"enabled":false}` sans
  autotest configuré ; sinon `200` avec `"ok":true` tant que la dernière réussite date de moins de
  `TESTANDFIX_SELFTEST_MAX_AGE_MINUTES` (par défaut 2 × l'intervalle + 30 min, soit 750 min), `503` avec
  `"ok":false` au-delà ou s'il n'y a jamais eu de réussite (cas d'une installation neuve pendant la
  première minute). Le corps ne contient que des heures, des durées et des codes : ni hôte, ni
  domaine, ni adresse.
- **IMAP chiffré** (US-023) : `TESTANDFIX_IMAP_SECURE=true` (par défaut) ouvre une connexion TLS directe
  (993) ; sinon STARTTLS si le serveur le propose. Le certificat est toujours vérifié (chaîne et
  nom d'hôte), il n'existe pas de réglage pour couper la vérification ; pour un serveur à certificat
  autosigné ou privé, `TESTANDFIX_IMAP_TLS_CA` donne l'autorité à croire (texte PEM ou chemin d'un
  fichier), à la place des autorités publiques. `/api/mail/status` indique le protocole TLS de la
  connexion et si le certificat a été vérifié.

## Whois et RDAP (2026-11-12)

L'outil RDAP devient « Whois et RDAP » (`/whois`, les anciennes adresses `/rdap/...` y mènent ; id d'outil inchangé
`rdap`, pour l'historique). Il interroge le registre puis le bureau d'enregistrement, car leurs données divergent
parfois (date d'échéance du contrat, contacts, revendeur) : `server/src/lib/whois/lookup.ts`.

| Partie | Source 1 | Repli |
|---|---|---|
| Registre | RDAP, adresse lue dans l'amorçage IANA (`data.iana.org/rdap/dns.json`, RFC 9224) | WHOIS port 43, serveur donné par `whois.iana.org` ; chaque adresse du nom est essayée |
| Bureau d'enregistrement | RDAP au lien `rel: related` de la réponse du registre (ICANN RDAP TIG 2.2 §3.2), sinon son URL de base (RDAP Response Profile 2.2 §2.4.6, ou registre IANA « Registrar IDs ») | WHOIS port 43 au « Registrar WHOIS Server » du registre ; un 404 RDAP du bureau est définitif (Profile §2.11.1) |

- Politesse (`limiter.ts`, partagé par tout le processus) : une requête à la fois par serveur, 1 s entre deux requêtes
  RDAP et 3 s entre deux requêtes WHOIS au même serveur, 6 requêtes en vol au plus ; après un échec, pause de 5 s
  doublée à chaque échec (5 min au plus) ; un 429 bloque le serveur le temps de son Retry-After (RFC 7480 §5.5,
  10 min au plus) et la recherche passe à l'autre protocole. Aucun registre interrogé ne publie de limite chiffrée
  (Afnic : limitation « par IP » sans chiffre) : ces valeurs sont des choix prudents.
- Données : dates, statuts EPP expliqués (RFC 5731, RFC 3915, correspondance RDAP RFC 8056, textes d'après la page
  « EPP Status Codes » de l'ICANN), bureau d'enregistrement, revendeur, contacts (titulaire, administratif, technique)
  sauf masqués (membre `redacted` RFC 9537, remarques, valeurs de remplacement, attribut `anonymous` d'Afnic), serveurs
  de noms, DNSSEC. Les écarts registre / bureau sont listés champ par champ.
- Adresses IPv4 (enregistrements A, demandées le 2026-11-12) : lues dans le DNS en parallèle du Whois, pas dans le
  Whois ; liste vide quand le nom n'en a pas, champ absent quand le DNS n'a pas répondu (colonne `ipv4_a` de l'export).
- Une liste : `POST /api/whois/batch/stream`, 100 domaines au plus, 4 à la fois, lignes envoyées au fil de l'eau ;
  export CSV pour Excel (point-virgule, BOM), CSV virgules et JSON côté navigateur.
