# Validation interne de la réécriture

Les contrôles décrits ici s'appliquent à l'implémentation locale, sans crate tierce en production. Les résultats antérieurs obtenus avec RustCrypto/napi-rs ne valident pas cette réécriture. Les preuves exécutables associent chaque résultat aux sources et lockfiles exacts ; les résultats non exécutés restent explicitement hors preuve.

Le propriétaire demande une CI préparée uniquement : aucun envoi sur GitHub ni aucune exécution distante n'est requis ou effectué. Une configuration de runner et une compilation croisée ne prouvent pas l'exécution sur cette plateforme.

## Contrôles et critères

| Contrôle | Portée et critère |
| --- | --- |
| Production sans crate tierce | Graphe exact des trois crates locales ; `--frozen` dans un cache Cargo vide et un namespace réseau Linux isolé ; inspection des imports du module natif ; `.reports/production-isolation.json` |
| Primitives postquantiques | 195 cas ACVP officiels visant directement le code local : 80 ML-KEM-1024 et 115 ML-DSA-87 ; aucune sortie différente acceptée |
| Hash, XOF et dérivation | 1 771 cas officiels : SHA-512 1 024, SHA3-256 151, SHA3-512 86, SHAKE128 269, SHAKE256 41, HMAC-SHA-512 150, HKDF-SHA-512 50 ; limites d'API et fractionnement couverts séparément |
| ChaCha20 et Poly1305 | Vecteurs RFC 8439, 256 cas Poly1305 calculés par une référence Python en entiers arbitraires et 128 cas AEAD produits par OpenSSL ; cas vides, retenues et frontières de blocs |
| Algèbre | Opérations de corps, NTT/inverse et multiplication négacyclique comparées aux définitions arithmétiques lentes ; codecs et rejets canoniques |
| Protocole | Vecteur PQRS v1 immutable, erreurs d'AAD/contexte/clés, limites exactes, formats incohérents, altérations et messages vides |
| Interopérabilité | 18 échanges dirigés Rust/Node/OpenSSL pour messages de 0, 15 et 65 536 octets, contextes 0/8/255 ; vérification du vecteur indépendant immuable |
| Système et secrets | Échec d'aléa immédiat/partiel, interruption/reprise, retour de longueur invalide, effacement des buffers détenus, destruction et concurrence |
| Miri plateforme | Cinq tests du module local plateforme sous l'interpréteur Rust ; cœur cryptographique et binding Node non exécutés sous Miri |
| Node-API locale | Vues partagées/détachées, getters réentrants, tags de types, prototypes falsifiés, GC, terminaison de Workers et injections d'échecs ; artefact de test séparé de `native/` |
| ASan de la frontière native | Linux x64 GNU, Node 22 ; Rust cœur/platform/binding instrumentés ; baseline hôte puis contrôle négatif devant détecter un overflow connu avant les tests API/GC/Workers et échecs injectés ; aucune suppression de fuite |
| Fuzzing | Trois cibles ASan : parseurs, opérations complètes, primitives et fractionnement ; aucune panique, violation mémoire, acceptation d'un tag altéré ou divergence attendue |
| Outils | Audit du lockfile du workspace fuzz et des dépendances TypeScript isolées ; aucune vulnérabilité/alerte non traitée |
| Archives | Installation hors ligne des archives exactes dans un projet vide, CJS/ESM, API et destruction sous Node 22 et 24 sur chaque cible réellement exécutée |

Les tests ACVP de signatures reconstruisent explicitement le préfixe de contexte FIPS pour les cas externes ; ils ne se contentent pas d'un aller-retour avec les mêmes fonctions. Les cas HMAC peuvent vérifier des MAC tronqués. Les cas HKDF-SHA-512 proviennent de NIST KDA-HKDF Sp800-56Cr1 ; les exemples RFC 5869 ne sont pas présentés comme des vecteurs SHA-512. Les groupes préhash/externalMu et les fonctions de hash orientées bits ne font pas partie de l'API du paquet.

## Mesures de canaux auxiliaires

Le harness `validation/timing/` est isolé du graphe de production. Il mesure des scénarios symétriques, le secret de rejet ML-KEM avec clé publique et ciphertext fixes, la position d'un octet de tag invalide, la comparaison ML-KEM et l'arithmétique de corps. La préparation des classes est exclue de la mesure ; les pools de clés ont la même taille et les tableaux symétriques sont copiés vers des adresses identiques pour limiter les biais de cache.

Chaque scénario réalise trois répétitions de 100 000 mesures, classes mélangées, 2 000 mesures de chauffe et test de Welch. Un `|t| > 4,5` dans au moins deux répétitions signale une différence reproductible et fait échouer la commande. Un signal doit être expliqué ou corrigé ; une machine bruyante n'autorise pas à ignorer arbitrairement l'échec. Le rapport décrit le matériel, les sources, la commande et les journaux.

L'absence de signal ne prouve pas le temps constant. Ces mesures n'évaluent ni les attaques physiques ni tous les secrets, toutes les instructions, plateformes ou variantes de compilateur. Le rejet probabiliste de ML-DSA rend sa durée totale variable ; aucune garantie de durée constante de signature n'est annoncée. La [revue ciblée du code machine](CODEGEN.md) complète ces mesures sans constituer une preuve formelle. La CI préparée capture les assembleurs x64 et ARM64 et bloque certains motifs d'instructions : cette compilation croisée ne prouve pas une exécution ARM64 ni une inspection du module Node après édition de liens.

## Reproduction et rapports

```sh
# Les trois commandes ci-dessous ne téléchargent aucune dépendance Cargo.
cargo test --workspace --frozen
node validation/production_graph.mjs
cargo build -p post-quantum-core --example interop --frozen

# Intégrité des références officielles et conversions, sans réseau.
python3 validation/fetch_acvp.py --check
python3 validation/prepare_vectors.py --check
python3 validation/fetch_primitives.py --check

# OpenSSL >=3.5, uniquement pour les tests.
python3 validation/symmetric_reference.py --check
python3 validation/openssl_interop.py --node

# Outils de développement dans leurs périmètres isolés.
npm ci --prefix validation/typescript --ignore-scripts
cargo install cargo-audit --version 0.22.2 --locked
node scripts/validate.mjs
node validation/ffi_failures.mjs
# Linux x64 GNU, gcc/libasan et Node 22 ou 24 ; artefacts séparés.
node validation/ffi_asan.mjs
node validation/timing/run.mjs
node validation/codegen.mjs --target x86_64-unknown-linux-gnu
node validation/codegen.mjs --target aarch64-unknown-linux-gnu
python3 validation/linked_codegen.py
rustup toolchain install nightly-2026-09-21 --profile minimal --component miri
cargo +nightly-2026-09-21 miri test -p post-quantum-platform --lib --frozen

cargo +nightly-2026-09-21 install cargo-fuzz --version 0.13.2 --locked
node validation/fuzz.mjs
node scripts/benchmark.mjs --iterations 30
```

`.reports/validation.json` consigne les étapes de la suite locale et leur résultat ; `.reports/production-isolation.json`, `tooling-audit.json`, `ffi-failures.json`, `ffi-asan.json` et `timing.json` précisent leurs périmètres respectifs. ASan utilise un runtime partagé dont la version et le digest sont consignés ; Node/V8 et la bibliothèque standard Rust précompilée ne sont pas instrumentés. La réussite ne prouve donc pas l'absence de toute erreur mémoire. Les logs de fuzz et campagnes supplémentaires sont placés sous `artifacts/validation/`. Aucun nombre de campagnes anciennes n'est une preuve pour un nouveau snapshot.

La CI ASan cible Node 22. Le contrôle local Node 24.21.0 rencontre des fuites de l'hôte même sans charger le binding ; aucun succès ASan sous Node 24 n'est revendiqué et aucune suppression ne les masque. Le wrapper accepte un exécutable Node 24 pour reproduire cette limite, en faisant échouer sa baseline. Les tests fonctionnels et d'archives Node 24 restent exigés indépendamment.

Une livraison complète reste soumise au commit propre et aux preuves d'exécution de toutes les cellules Linux x64/ARM64 glibc/musl, macOS x64/ARM64 et Windows x64 avec Node 22 et 24. Les rapports locaux portent une empreinte du contenu ; seuls les résultats des cellules GitHub Actions effectivement terminées comptent pour la matrice distante. Les preuves bornées Kani sont décrites dans [ASSURANCE.md](ASSURANCE.md).

Aucun de ces contrôles n'est un audit indépendant, une certification CAVP/FIPS, une preuve de la composition PQRS ou une preuve absolue de résistance quantique. La [provenance](PROVENANCE.md) et le [modèle de sécurité](SECURITY.md) indiquent les hypothèses maintenues.
