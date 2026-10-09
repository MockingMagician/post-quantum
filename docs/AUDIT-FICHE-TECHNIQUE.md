# Mesh — Fiche de cadrage pour un audit cryptographique indépendant

Préparée le 29 septembre 2026. Annexe transmissible aux spécialistes, complément du [brief de prospection](BRIEF-AUDIT-ASSOCIATION.md) et du [dossier préparatoire d’audit](AUDIT.md).

## Projet et objectif

Mesh Network Association porte cette bibliothèque pour une **future évolution de Mesh, avant intégration**. La demande concerne la bibliothèque `post-quantum`, pas un audit global de la messagerie, de son infrastructure ou de ses autres composants.

Nous recherchons une revue indépendante spécialisée et une prise en charge intégrale du coût par soutien en compétences, mécénat ou programme de financement. Un premier lot ciblé est envisageable si le rapport distingue clairement la couverture obtenue du travail restant.

## État technique

| Élément | Description |
| --- | --- |
| Architecture | Cœur Rust utilisable indépendamment ; module natif Node-API et interface typée TypeScript. |
| Primitives | ML-KEM-1024, ML-DSA-87, HKDF-SHA-512 et ChaCha20-Poly1305. |
| Provenance | Primitives et binding Node-API écrits localement ; trois crates locales dans le graphe de production. La bibliothèque standard, le compilateur, le système et Node.js restent dans la base de confiance. |
| Composition | Enveloppe propre au paquet `PQRSv1`, décrite dans le format ; elle n’est pas un protocole standardisé. |
| Licences | Code original sous MIT ou Apache-2.0 ; vecteurs NIST avec notice distincte. |
| Validation | Documentation de tests Rust/Node, vecteurs NIST, interopérabilité OpenSSL, fuzzing et contrôles ciblés. Les résultats exécutés et les limites sont distingués dans le rapport de validation. |
| Assurance indépendante | Aucun audit indépendant ni certification FIPS. Les tests et preuves ciblées ne constituent pas une preuve globale de sécurité ou de temps constant. |

La [provenance](PROVENANCE.md), le [modèle de sécurité](SECURITY.md), le [format](FORMAT.md), les [résultats de validation](VALIDATION.md) et les [preuves ciblées](ASSURANCE.md) sont disponibles dans le dossier technique.

## Périmètre proposé, à chiffrer et délimiter avec l’auditeur

1. **Implémentations cryptographiques :** conformité ML-KEM/ML-DSA aux normes FIPS 203/204, encodages, entrées malformées et rejet implicite ; examen des primitives symétriques locales et de leurs usages.
2. **Composition :** dérivation des clés, liaison au destinataire, authentification, données associées et contextes de signature ; cohérence avec les garanties annoncées.
3. **Protection des secrets :** aléa, effacement, comportement sur erreurs et fuites par canaux auxiliaires, notamment le temps d’exécution ; examen des binaires optimisés sur les plateformes retenues.
4. **Interface native :** frontière Rust/Node-API, mémoire, pointeurs, concurrence, destruction des clés, arrêt des Workers et traitement des erreurs.

Le paquet laisse à l’application l’authentification des clés publiques, les identités, le stockage, la rotation/révocation et la protection contre le rejeu. Il ne fournit pas de confidentialité persistante : compromettre ultérieurement la clé de déchiffrement peut permettre de lire d’anciens messages enregistrés. L’audit de la bibliothèque ne couvrira pas automatiquement sa future intégration dans Mesh.

## Livrables et préparation

Attendus : rapport écrit avec périmètre et exclusions, constats classés par gravité, reproductions minimales et recommandations ; revue des corrections ; coordination de la diffusion des détails exploitables après correction.

Avant le démarrage, l’équipe et l’auditeur fixeront le commit exact, les empreintes des artefacts, les plateformes et versions couvertes, le calendrier, le temps d’accompagnement et les modalités de publication. Une revue limitée devra être présentée comme telle.

Le responsable technique fournira ses coordonnées, l’accès au code et les éléments de validation correspondant à la version retenue. L’URL configurée dans ce dépôt est [MockingMagician/post-quantum](https://github.com/MockingMagician/post-quantum) ; son accessibilité publique n’a pas pu être confirmée lors de la préparation. Prévoir un accès convenu si nécessaire.
