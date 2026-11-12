# SpamAssassin pour check

Image `spamd` utilisée par le test de mail. L'application lui envoie chaque message reçu par le
protocole SPAMC/1.5 (commande `REPORT`, port 783) et transforme chaque règle déclenchée en anomalie
expliquée par la base de situations. Si `spamd` ne répond pas, la note est calculée sans lui et le
rapport le signale.

## Contenu

- Debian 13 (trixie), paquets `spamassassin`, `spamd`, `spamc`, `unbound`.
- Règles mises à jour par `sa-update` à la construction puis à chaque démarrage (en cas d'échec,
  les règles de l'image restent en service).
- Bayes désactivé (`use_bayes 0`) : deux analyses du même message donnent le même résultat.
- Tests réseau actifs (listes DNSBL et URIBL, SPF, DKIM) à travers un Unbound local réservé à
  SpamAssassin, `cache-max-ttl: 0` : chaque requête remonte aux serveurs autoritaires. Spamhaus
  refuse les résolveurs publics, d'où ce résolveur récursif propre.
- `spamd` écoute sur `0.0.0.0:783` et n'accepte que la boucle locale et les réseaux privés
  utilisés par Docker (`SPAMD_ALLOWED_IPS`). Ne publiez pas ce port sur Internet.

## Utilisation

```sh
docker build -t check-spamassassin docker/spamassassin
docker run -d --name check-spamd -p 127.0.0.1:783:783 check-spamassassin
# vérification : le message de test GTUBE doit dépasser 1 000 points
printf 'Subject: test\r\n\r\nXJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X\r\n' \
  | docker exec -i check-spamd spamc -R
```

Variables : `SPAMD_ALLOWED_IPS` (liste séparée par des virgules), `SPAMD_MAX_CHILDREN` (4 par défaut).
Côté application : `SPAMD_HOST` et `SPAMD_PORT`.
