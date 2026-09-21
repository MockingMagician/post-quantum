# Origine du code et référentiel normatif

Le cœur cryptographique, la frontière Node-API et la couche système sont des implémentations locales écrites pour ce projet d'après les spécifications ci-dessous. Aucun source de RustCrypto, napi-rs, OpenSSL, PQClean ou autre bibliothèque tierce n'est incorporé dans les crates de production. Les constantes et formats mathématiques prescrits par les normes sont conservés. Cela ne constitue ni une certification de processus « clean room », ni une invention des algorithmes.

Le graphe de production contient trois crates locales : `post-quantum-core`, `post-quantum-platform` et `post-quantum-node`. Rust et sa bibliothèque standard, le linker/SDK, les bibliothèques système, le système d'exploitation et l'hôte Node-API font partie de la base de confiance. « Sans crate tierce » ne signifie donc pas sans compilateur, bibliothèque standard ou API système.

| Élément | Référence de conception |
| --- | --- |
| ML-KEM-1024, codecs, NTT, rejet implicite | [FIPS 203, publication finale du 13 août 2024](https://csrc.nist.gov/pubs/fips/203/final) |
| ML-DSA-87, échantillonnage, NTT, encodage canonique | [FIPS 204, publication finale du 13 août 2024](https://csrc.nist.gov/pubs/fips/204/final) |
| SHA-512 | [FIPS 180-4](https://doi.org/10.6028/NIST.FIPS.180-4) |
| SHA3-256, SHA3-512, SHAKE128, SHAKE256 | [FIPS 202](https://doi.org/10.6028/NIST.FIPS.202) |
| HMAC-SHA-512 et HKDF-SHA-512 | [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104), [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) |
| ChaCha20-Poly1305 | [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) |
| Enveloppes, types de clés et séparation des usages | [Format propre au paquet](FORMAT.md) |
| Binding natif et nettoyage d'environnement | [Node-API](https://nodejs.org/api/n-api.html) |
| Aléa système | `getrandom` sur Linux, `getentropy` sur macOS, `BCryptGenRandom` avec `BCRYPT_USE_SYSTEM_PREFERRED_RNG` sur Windows |

## Errata examinés le 21 septembre 2026

Les tableaux NIST décrivent des corrections potentielles et ne constituent pas eux-mêmes une nouvelle édition normative.

- [FIPS 203 : tableau officiel](https://csrc.nist.gov/files/pubs/fips/203/final/docs/fips-203-potential-updates.xlsx), SHA-256 `edf899c89762449f43d7713883caeefc2e4ae9ae98d5a76b339547db22cb3ac7` : entrée zêta d'indice zéro incluse pour l'indexation mais non utilisée par les NTT ; commentaire du déchiffrement devant nommer `w`, pas `v`.
- [FIPS 204 : tableau officiel, actualisé le 31 juillet 2026](https://csrc.nist.gov/files/pubs/fips/204/final/docs/fips-204-potential-updates.xlsx), SHA-256 `5bc93ce63bc647e6d1d456cb2d3a171426c15aca4a7a0e0edd40d08b7a34c793` : évaluation NTT unique, transcript `M'`, ordre `mu || w1`, borne exacte de `UseHint`, clarifications de réduction de Montgomery et minimum de limite d'itérations de signature porté de 814 à 821. Les tests algébriques et les vecteurs vérifient les sorties attendues ; aucune ancienne valeur de limite 814 n'est utilisée comme argument de sûreté.

La révision exacte des vecteurs NIST est figée au commit ACVP-Server `975de31eb83d87039ec88934fdc47d8c312b892d`. Les manifests de validation consignent les URL, empreintes, groupes et cas retenus. Les fichiers `.kat` sont des données converties pour les tests, pas du code tiers. La notice NIST demeure dans `validation/acvp/NOTICE.md`.

## Séparation des outils

OpenSSL et Python servent uniquement de références de test. libFuzzer est une dépendance du workspace exclu `fuzz/`; TypeScript et ses types sont isolés sous `validation/typescript/`. Le graphe, les imports du module natif et une compilation avec cache Cargo vide et réseau isolé sont contrôlés par `validation/production_graph.mjs`. Les dépendances des outils sont analysées séparément par `validation/audit_tooling.mjs`.

La vérification des empreintes et du graphe prouve une propriété observable des artefacts testés ; l'origine du code repose aussi sur la revue humaine des sources. Aucun audit indépendant ni preuve formelle de cette nouvelle implémentation n'est annoncé.
