# Dossier préparatoire d'audit indépendant

## Objet

Paquet Node.js typé TypeScript dont les opérations cryptographiques sont implémentées en Rust. Le cœur utilise ML-KEM-1024, ML-DSA-87, HKDF-SHA-512 et ChaCha20-Poly1305, avec une enveloppe locale `PQRSv1`. Trois crates locales constituent le graphe de production ; la bibliothèque standard, le compilateur, le système d'exploitation et Node-API restent dans la base de confiance. Le code original est offert sous `MIT OR Apache-2.0`, et les vecteurs ACVP NIST conservent leur notice.

## Mission proposée

1. Vérifier la conformité de l'implémentation ML-KEM/ML-DSA et les encodages canoniques contre FIPS 203/204, en portant une attention particulière au rejet implicite et aux entrées malformées.
2. Examiner les fuites de canaux auxiliaires dans les fonctions traitant des secrets et dans les **binaires optimisés distribués**, sur les cibles effectivement livrées.
3. Auditer la frontière Node-API : ABI, pointeurs, propriété, concurrence, fin de Worker, destruction/effacement et erreurs.
4. Examiner la composition du protocole et le modèle de menace : liaison des clés, AAD/contexte, authentification, rejouement et limites de confidentialité persistante.

Le périmètre doit être fixé à un commit et aux empreintes de ses artefacts. Les livrables attendus sont un rapport de constats classés par gravité, des reproductions minimales, des recommandations, puis une revue des corrections. Le rapport public ne doit révéler les détails exploitables qu'après coordination des corrections.

## Matériaux fournis

- [Modèle de sécurité](SECURITY.md), [format](FORMAT.md), [provenance](PROVENANCE.md) et [preuve ciblée/frontière native](ASSURANCE.md).
- [Validation et commandes reproductibles](VALIDATION.md), vecteurs NIST avec manifest et notice, tests Rust/Node, interopérabilité OpenSSL, fuzzing et rapports de code compilé.
- Workflow GitHub de sept plateformes et deux versions Node ; chaque cellule non encore terminée doit rester marquée comme non validée.

Il n'existe à ce stade ni audit indépendant, ni certification FIPS, ni preuve globale de résistance postquantique ou de temps constant. Aucune demande de financement ou prise de contact n'a été envoyée dans la préparation de ce dossier.
