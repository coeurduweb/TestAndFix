# Base de situations : format

Chaque fichier `knowledge/situations/<famille>.yaml` contient une liste d'entrées. Une entrée décrit
une anomalie détectable sur un e-mail reçu ou sur un domaine, et la correction à proposer.
Le moteur de diagnostic choisit les entrées qui s'appliquent et remplace les variables par les
valeurs réelles du test : le conseil affiché est donc personnalisé.

```yaml
- id: spf.lookup_limit            # unique, minuscules, famille.nom
  family: spf                     # voir la liste des familles ci-dessous
  severity: high                  # critical | high | medium | low | info
  penalty: 1.0                    # points retirés sur 10 (0 pour info)
  detect:                         # comment le moteur reconnaît la situation
    signal: "spf.result == permerror && spf.reason ~ /too many DNS lookups/i"
    notes: "La RFC 7208 §4.6.4 fixe la limite à 10 mécanismes qui déclenchent une requête DNS."
  sa_rules: []                    # noms de règles SpamAssassin rattachées (famille spamassassin surtout)
  title: "Votre SPF dépasse 10 requêtes DNS"
  why: >                          # 1 à 3 phrases, concrètes, sans jargon gratuit
    Au-delà de 10 requêtes, le destinataire arrête l'évaluation et considère le SPF en erreur
    permanente : {domain} perd le bénéfice du SPF pour tous ses envois.
  fix:                            # étapes ordonnées, impératif, vouvoiement
    - "Retirez les include: des services que {domain} n'utilise plus."
    - "Remplacez les mécanismes a et mx par les adresses ip4: correspondantes."
  fix_by_provider:                # facultatif ; clés de la liste des fournisseurs ci-dessous
    google_workspace: "..."
  example_bad: "v=spf1 include:a include:b ... ~all"     # facultatif
  example_good: "v=spf1 ip4:203.0.113.10 include:_spf.google.com ~all"
  references:                     # URL de sources primaires (RFC, documentation officielle)
    - https://www.rfc-editor.org/rfc/rfc7208#section-4.6.4
```

## Variables utilisables dans `why`, `fix`, `fix_by_provider`, `example_*`

| Variable | Valeur |
|---|---|
| `{domain}` | domaine de l'adresse From |
| `{envelope_domain}` | domaine du Return-Path / MAIL FROM |
| `{dkim_domain}` | domaine d= de la signature DKIM |
| `{selector}` | sélecteur DKIM s= |
| `{ip}` | IP de l'expéditeur vue par notre serveur |
| `{ptr}` | reverse DNS de cette IP |
| `{helo}` | nom annoncé dans HELO/EHLO |
| `{spf_record}` | enregistrement SPF actuel |
| `{dmarc_record}` | enregistrement DMARC actuel |
| `{suggested_record}` | enregistrement corrigé calculé par le moteur |
| `{provider}` | fournisseur d'envoi détecté (nom lisible) |
| `{lookup_count}` | nombre de requêtes DNS du SPF |
| `{list_name}` / `{delist_url}` | liste noire concernée et son lien de délistage |
| `{rule}` / `{rule_score}` | règle SpamAssassin et son score |
| `{url}` | lien concerné dans le message |
| `{value}` | valeur mesurée générique (taille, ratio, nombre…) |
| `{target}` / `{final}` | URL visée par une redirection / URL finale de la chaîne |
| `{status}` / `{ttfb}` | statut HTTP d'un saut / temps jusqu'au premier octet |
| `{subdomain}` / `{service}` | sous-domaine concerné / service tiers visé par son CNAME |

## Familles

`spf`, `dkim`, `dmarc`, `arc`, `bimi`, `alignment`, `rdns`, `helo`, `blacklist`, `tls`, `mta-sts`,
`dnssec`, `mx`, `headers`, `content`, `html`, `links`, `images`, `attachments`, `unsubscribe`,
`bulk-sender`, `reputation`, `spamassassin`, `infrastructure`, `dmarc-report`, `ip`, `phishing`, `redirects`, `link`, `subdomains`.

## Fournisseurs (clés de `fix_by_provider`)

`google_workspace`, `microsoft_365`, `ovh`, `o2switch`, `cpanel`, `plesk`, `ionos`, `gandi`,
`infomaniak`, `zoho`, `proton`, `brevo`, `mailchimp`, `mailjet`, `sendgrid`, `mailgun`, `amazon_ses`,
`postmark`, `sparkpost`, `hubspot`, `salesforce`, `wordpress`, `cloudflare_dns`, `postfix`, `exim`.

## Règles de rédaction

- Français, vouvoiement, phrases courtes. Aucun tiret cadratin ni demi-cadratin (— –).
- Une correction se fait : dire où cliquer ou quoi écrire, pas « vérifiez votre configuration ».
- Ne jamais inventer un chiffre, une limite ou une règle : citer la source primaire dans `references`.
- `why` parle des conséquences réelles (spam, rejet, perte d'alignement), pas de la théorie.
