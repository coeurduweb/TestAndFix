# check-agent : vider les caches DNS et le cache fichier d'une machine Linux

Ce dossier contient un petit composant autonome de l'outil `check`. Il permet à un
bouton de l'interface web de vider, sur une machine Linux :

1. tous les caches DNS locaux (résolveur système, démons de cache, résolveurs récursifs) ;
2. le cache de pages du noyau (le « cache fichier »).

Deux machines sont visées :

- **le serveur** qui héberge l'outil : l'application tourne dans Docker et joint l'agent de l'hôte ;
- **le poste Linux de l'utilisateur** : son navigateur joint l'agent sur `127.0.0.1`.

| Fichier | Rôle |
|---|---|
| `flush-caches.sh` | Script POSIX sh, exécuté en root. Détecte et purge tout ce qui est présent. |
| `check-agent.py` | Agent HTTP (Python 3.6+, bibliothèque standard seule), écoute sur `127.0.0.1:47625`. |
| `install.sh` | Installe le script et l'agent, crée l'utilisateur, la règle sudoers, le jeton et le service. |
| `tests/` | Tests unitaires de l'agent et matrice de tests Docker multi-distributions. |

## flush-caches.sh

```
flush-caches.sh [--dns-only | --page-cache-only] [--dry-run] [--json]
```

| Option | Effet |
|---|---|
| `--dns-only` | Ne vide que les caches DNS. |
| `--page-cache-only` | Ne vide que le cache de pages du noyau. |
| `--dry-run` | Détecte et annonce ce qui serait fait, ne change rien. Utilisable sans être root. |
| `--json` | Le journal lisible passe sur stderr, la dernière ligne de stdout est un objet JSON. |

### Ce que fait chaque cible

Un démon est traité seulement s'il tourne (détecté dans `/proc`). Sinon la cible est `absent`.
Seuls les processus du même espace de noms PID que le script sont traités : un démon qui tourne
dans un autre conteneur (celui d'une autre application du serveur) n'est jamais signalé ni purgé.
Sa cible est `skipped` avec la raison, jamais `failed`. Un processus dont l'espace de noms ne
peut pas être déterminé est laissé de côté de la même façon, et la raison le dit.

| Cible | Commande utilisée |
|---|---|
| systemd-resolved | `resolvectl flush-caches`, sinon `systemd-resolve --flush-caches`, sinon signal `USR2` |
| nscd | `nscd -i hosts`, sinon redémarrage du service |
| unscd | `nscd -i hosts`, sinon redémarrage du service |
| dnsmasq (autonome, lancé par NetworkManager, lancé par libvirt) | signal `HUP` à chaque processus |
| unbound | `unbound-control flush_zone .` puis `flush_infra all` et `flush_bogus`, sinon `reload`, sinon redémarrage, sinon `HUP` |
| BIND (named) | `rndc flush`, sinon redémarrage du service |
| PowerDNS Recursor | `rec_control wipe-cache '$'`, sinon redémarrage |
| Knot Resolver (kresd) | `kresctl cache clear` (version 6), sinon `cache.clear()` sur le socket de contrôle (socat, python3 ou nc), sinon redémarrage |
| dnscrypt-proxy | redémarrage du service (il n'a pas de commande de purge) |
| stubby | redémarrage du service |
| sssd | `sss_cache -E` |
| CoreDNS local | signal `USR1` (rechargement du Corefile), sinon redémarrage |
| pdnsd | `pdnsd-ctl empty-cache`, sinon redémarrage |
| cache de pages | `sync` puis `echo 3 > /proc/sys/vm/drop_caches` |

Les redémarrages et rechargements passent par l'init détecté : systemd (`systemctl`),
OpenRC (`rc-service`), runit (`sv`), s6 (`s6-svc`) ou SysV (`service` ou `/etc/init.d`).
Un redémarrage n'est tenté qu'en dernier recours, et seulement pour un démon qui tourne déjà.

Si `/proc/sys/vm/drop_caches` n'est pas inscriptible dans un conteneur sans privilège,
l'état est `skipped` (pas une erreur). Hors conteneur, c'est `failed`.

### Sortie JSON

```json
{"host":"srv1","distro":"Debian GNU/Linux 12 (bookworm)","kernel":"6.1.0-18-amd64","init":"systemd",
 "dry_run":false,
 "actions":[{"target":"unbound","status":"flushed","detail":"unbound-control flush_zone ., flush_infra all, flush_bogus"}],
 "page_cache":{"before_kb":812344,"after_kb":120344,"status":"flushed","detail":"sync; echo 3 > /proc/sys/vm/drop_caches"},
 "ok":true}
```

`status` vaut `flushed` (purgé), `absent` (démon non présent), `failed` (échec) ou `skipped`
(non exécuté : mode `--dry-run`, ou purge impossible sans que ce soit une erreur).
`ok` est `false` dès qu'une cible est `failed`.

### Codes de sortie

| Code | Signification |
|---|---|
| 0 | Succès (les cibles absentes ou ignorées ne comptent pas comme des échecs) |
| 1 | Au moins une purge a échoué |
| 2 | Option invalide |
| 3 | Pas root (hors `--dry-run`) |

Le script ne touche jamais à une configuration, ne supprime aucun fichier et n'arrête aucun service.

## check-agent.py

Écoute par défaut sur `127.0.0.1:47625`.

| Route | Rôle |
|---|---|
| `GET /health` | Répond sans jeton `{"ok":true,"authenticated":false,...}`. Avec un jeton valide, `authenticated` vaut `true`. Sert à détecter l'agent et à valider le jeton. |
| `POST /flush` | Jeton obligatoire. Corps JSON optionnel `{"dns":true,"page_cache":true}` (les deux à vrai par défaut). Lance `flush-caches.sh --json` et renvoie son JSON, avec en plus `exit_code`. |
| `OPTIONS *` | Préflight CORS, avec `Access-Control-Allow-Private-Network: true` (Private Network Access de Chrome). |

Codes HTTP : 200 (le JSON dit si tout est `ok`), 400 corps invalide, 401 jeton absent ou faux,
403 origine refusée, 413 corps trop gros, 429 trop de purges (une toutes les 10 secondes, en-tête `Retry-After`),
502 le script n'a pas renvoyé de JSON (par exemple `sudo` refusé).

Configuration par variables d'environnement :

| Variable | Défaut | Rôle |
|---|---|---|
| `CHECK_AGENT_TOKEN` | | Jeton, prioritaire sur le fichier |
| `CHECK_AGENT_TOKEN_FILE` | `/etc/check-agent/token` | Fichier du jeton (16 caractères minimum) |
| `CHECK_AGENT_ORIGIN` | vide | Origine(s) web autorisées pour CORS, séparées par des virgules |
| `CHECK_AGENT_BIND` / `CHECK_AGENT_PORT` | `127.0.0.1` / `47625` | Adresse et port d'écoute |
| `CHECK_AGENT_SCRIPT` | `/usr/local/lib/check-agent/flush-caches.sh` | Chemin du script |
| `CHECK_AGENT_MIN_INTERVAL` | `10` | Secondes entre deux purges |

Si l'agent n'est pas root, il lance le script par `sudo -n`. Il refuse de démarrer sans jeton.
Les journaux vont sur stderr (journald, ou `/var/log/check-agent.log` avec OpenRC et SysV).

Appel depuis le navigateur :

```js
const r = await fetch('http://127.0.0.1:47625/flush', {
  method: 'POST',
  headers: {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'},
  body: JSON.stringify({dns: true, page_cache: true}),
});
const resultat = await r.json();
```

## Installation

Prérequis : Python 3.6 ou plus, `sudo` et `visudo` (sauf option `--root`).

```sh
cd agent
sudo ./install.sh --origin https://check.example.com
```

Le script copie `flush-caches.sh` et `check-agent.py` dans `/usr/local/lib/check-agent/`
(propriété de root, non modifiables par l'agent), crée l'utilisateur système `check-agent`,
écrit `/etc/sudoers.d/check-agent` (validé par `visudo -c`), génère le jeton dans
`/etc/check-agent/token` et installe un service selon l'init détecté : unité systemd,
script OpenRC ou script SysV. Le jeton est affiché une seule fois à l'installation.
Sur runit, s6 ou un init inconnu, aucun service n'est créé : la commande de lancement manuel est affichée.

Désinstallation complète : `sudo ./install.sh --uninstall`.

### Sur le serveur (application dans Docker)

L'agent tourne sur l'hôte et doit être joignable depuis le conteneur. Deux façons :

1. Écoute sur l'adresse du pont Docker (souvent `172.17.0.1`) :
   `sudo ./install.sh --bind 172.17.0.1 --origin https://check.example.com`.
   Le conteneur appelle `http://172.17.0.1:47625`.
2. Écoute sur `127.0.0.1` avec le conteneur en `network_mode: host`, ou
   `host.docker.internal:host-gateway` si l'agent écoute sur `0.0.0.0`.

Sur le serveur, c'est le backend qui appelle l'agent, pas le navigateur : le jeton reste côté serveur
(variable d'environnement du conteneur) et CORS n'a pas d'importance. Ne jamais exposer le port
sur Internet : pare-feu pour n'autoriser que le réseau Docker.

### Sur le poste de l'utilisateur

```sh
sudo ./install.sh --origin https://check.example.com
```

L'agent écoute sur `127.0.0.1`. L'utilisateur colle le jeton (`sudo cat /etc/check-agent/token`) dans
l'interface une fois. L'origine passée à `--origin` doit être exactement celle de la page
(schéma, hôte, port). Chrome demande le préflight Private Network Access : l'agent y répond.

## Sécurité

- **Jeton obligatoire** pour toute purge, comparé en temps constant. L'agent refuse de démarrer sans jeton.
- **Écoute locale par défaut** (`127.0.0.1`). Élargir l'adresse est un choix explicite.
- **CORS limité** à l'origine configurée. Une page d'une autre origine ne peut ni lire la réponse ni purger,
  même avec le jeton (403).
- **Pas de root permanent** : l'agent tourne sous un utilisateur dédié sans shell ni répertoire personnel.
  Une règle sudoers `NOPASSWD` ne vise qu'un fichier, `/usr/local/lib/check-agent/flush-caches.sh`,
  que l'utilisateur ne peut pas modifier. Ce script ne vide que des caches.
- **Débit limité** : une purge toutes les 10 secondes, une seule à la fois.
- L'unité systemd n'active pas `NoNewPrivileges`, car `sudo` en a besoin.
- Le jeton est lisible par root et par le groupe `check-agent` seulement (`0640`).
  Quiconque lit le jeton peut déclencher des purges de cache, rien d'autre.
- Le fichier de jeton n'est jamais écrasé par une réinstallation. Pour le changer : supprimer le fichier,
  relancer `install.sh`.

## Tests

```sh
python3 -m unittest discover -s agent/tests        # agent : jeton, CORS, préflight, débit
CHECK_AGENT_REAL_SCRIPT=1 python3 -m unittest discover -s agent/tests   # en conteneur seulement : lance aussi le vrai script (--dry-run)
sh agent/tests/run-docker-tests.sh                 # matrice Docker (nécessite docker)
sh agent/tests/run-docker-tests.sh debian:12 busybox   # une sélection
```

La matrice lance, dans des conteneurs sans privilège, `flush-caches.sh --json --dry-run` puis en réel,
sous `sh`, `bash`, `dash` et `busybox sh` quand ils existent, après avoir installé et démarré dnsmasq
(trois instances), unbound, BIND, nscd et, selon la distribution, PowerDNS Recursor, Knot Resolver ou systemd-resolved.
Limites connues : un conteneur sans privilège ne peut pas écrire `drop_caches` (le test attend `skipped`),
et un vrai systemd n'y tourne pas.
