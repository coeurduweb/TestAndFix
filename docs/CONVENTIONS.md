# Conventions pour les contributeurs (humains et agents)

- Code, commentaires et noms en anglais ; textes affichés en français, vouvoiement.
- Aucun tiret cadratin ni demi-cadratin (— –) dans les textes affichés ni dans la base de situations.
- Toute requête DNS passe par `ctx.dns()` (une `ResolveSession` neuve par action utilisateur). Jamais
  `node:dns`, jamais un résolveur public pour obtenir une vérité, jamais de cache entre deux actions.
- Toute requête HTTP vers une URL fournie par l'utilisateur passe par `safeGet` (`server/src/lib/net.ts`).
  Exception documentée : l'outil Redirections utilise `server/src/lib/http-trace.ts` (mêmes garanties :
  résolution depuis la racine, IP non publiques refusées à chaque saut, aucune connexion réutilisée) pour
  obtenir les en-têtes bruts, les temps et le TLS.
- Exception documentée : la propagation appelle `query()` directement vers les résolveurs publics et les
  autoritaires (c'est la mesure elle-même), et lit RIPEstat pour la géolocalisation lors de la qualification.
- Exception documentée : le flux OpenPhish est téléchargé au plus une fois par heure (une liste, pas une mesure).
- Exception documentée : les sources Certificate Transparency (crt.sh peut mettre 20 s avant le premier
  octet) passent par `server/src/lib/ct/http.ts`, qui réutilise `safeAgent` (mêmes protections SSRF,
  aucun cache) avec un délai plus long que celui de `safeGet`.
- Exception documentée (2026-11-12) : l'outil Whois et RDAP (`server/src/lib/whois/`) garde en mémoire les listes de
  l'IANA (amorçage RDAP selon son en-tête Expires, RFC 9224 §8 ; serveur WHOIS d'une extension 24 h ; registre des
  bureaux d'enregistrement 1 h au moins) et chaque réponse 10 minutes par carnet, par politesse envers les registres
  (demande de l'utilisateur). La page dit quand elle montre une réponse gardée ; « Mesurer à nouveau » interroge les
  serveurs. Il ouvre aussi des connexions TCP sortantes sur le port 43 (WHOIS, RFC 3912) après résolution depuis la
  racine, vers des adresses publiques seulement. Toute requête passe par le limiteur partagé (`limiter.ts`).
- Chaque outil de vérification renvoie un `CheckResult` (`server/src/tools/types.ts`) : `findings` produits
  par `explain()` (`server/src/knowledge/engine.ts`) avec l'id de la situation de la base, `passed` pour ce
  qui va bien, `unavailable` pour une source absente ou en panne (jamais bloquant).
- Un id de situation absent de la base passe par `fallback` dans `explain()`. `fallback` ne sert QUE
  quand l'id manque : une gravité calculée selon le contexte (poids d'une liste, politique en vigueur) se
  passe en `severity` / `penalty` au premier niveau. `npm run kb:coverage -w server` liste les ids émis
  par le code et absents de la base (hors contrôles réussis).
- Un outil = `server/src/tools/<id>/index.ts` exportant `tool: ServerTool`. Ne modifiez pas `app.ts`,
  `db.ts`, `config.ts`, `auth.ts`, `knowledge/engine.ts` : demandez la modification dans votre compte rendu.
- Tests : Vitest à côté du code (`*.test.ts`). Les tests réseau réels sont autorisés (port 53 et 443
  ouverts) mais doivent tolérer une source lente ; le port 25 sortant est bloqué sur le poste de dev.
- Résultats enregistrés dans l'historique avec `saveResult()` (`server/src/db.ts`).
