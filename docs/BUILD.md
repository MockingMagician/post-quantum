# Compilation, archives et validation des plateformes

Le paquet utilise une distribution native par plateforme avec un binding Node-API local : un paquet principal JavaScript/TypeScript et un paquet natif facultatif par plateforme. npm sélectionne ce dernier avec les champs `os`, `cpu` et `libc`. Aucun script d'installation ne télécharge ou ne compile un binaire. Les noms actuels restent provisoires et tous les manifestes portent `private: true` ; aucun workflow ne publie sur npm.

## Développement local

Prérequis : Rust 1.93.1, un compilateur/linker natif et Node.js 22 ou 24. Aucune installation npm n'est requise avant la compilation : les scripts du paquet n'ont aucune dépendance JavaScript. Les dépendances de validation TypeScript sont installées séparément sous `validation/typescript/`. Pour compiler depuis une archive des sources sans `.git`, utiliser un checkout Git : les métadonnées de provenance nécessitent l'inventaire des fichiers du dépôt.

```sh
npm run build
npm test
```

`build` lance Cargo avec `--release --frozen`, sélectionne la cible Rust de l'hôte et copie le cdylib dans `native/post_quantum.<plateforme>.node`. Une cible peut être imposée avec `npm run build -- --target x86_64-unknown-linux-musl` si le compilateur et les bibliothèques correspondants sont disponibles. Pour musl, le script désactive `crt-static`, nécessaire au chargement dynamique par Node.js. Le graphe de production et une compilation en réseau isolé, cache Cargo vide, sont vérifiés par `node validation/production_graph.mjs`. Les seules crates autorisées sont les trois crates locales cœur, plateforme et binding.

Le chargeur donne priorité au binaire de développement présent dans `native/`. Dans une archive npm, ce dossier est absent et le chargeur utilise exclusivement le paquet de plateforme de même version. ESM et CommonJS partagent la même instance native et les mêmes déclarations TypeScript.

## Préparer et installer les archives

Après stabilisation des sources :

```sh
npm run build
npm run pack:artifacts
npm run test:package
```

Les archives et leurs preuves se trouvent dans `dist/<plateforme>/` :

- Deux fichiers `.tgz` : paquet principal et paquet de plateforme.
- `manifest.json`, `SHA256SUMS`, copies exactes de `Cargo.lock` et `package-lock.json`.
- `platform-package/BUILD.json` : commande, versions des outils, cible, commit, état du checkout, empreinte de chaque source et du binaire.
- `runtime-node22.json` ou `runtime-node24.json` : résultat de l'installation et empreintes exactes des archives utilisées.

La compilation refuse une modification des sources pendant son exécution. La préparation des archives refuse les sources modifiées depuis la compilation. Recompiler après une modification, y compris documentaire, avant de produire une nouvelle archive.

`test:package` installe les deux archives dans un projet temporaire avec `--offline --ignore-scripts`, puis utilise réellement `require('post-quantum')` et `import('post-quantum')`. Il teste chiffrement/déchiffrement, signatures, altérations, import/export et destruction des clés. Il ne consulte pas le registre npm. Pour une installation locale manuelle, fournir simultanément les deux archives :

```sh
npm install --offline --ignore-scripts /chemin/post-quantum-1.0.0.tgz /chemin/post-quantum-linux-x64-gnu-1.0.0.tgz
```

Les autres paquets de plateforme, facultatifs, peuvent être absents. Les fichiers d'archives sont privés et ne constituent pas une publication publique disponible dans le registre.

## Matrice et critères de livraison

| Plateforme | Environnement CI | Node.js 22 | Node.js 24 |
| --- | --- | --- | --- |
| Linux x64 glibc | Ubuntu 22.04 | Consulter les rapports locaux | Consulter les rapports locaux |
| Linux x64 musl | Alpine 3.23 natif | Consulter les rapports locaux | Consulter les rapports locaux |
| Linux ARM64 glibc | Ubuntu 22.04 ARM64 | CI à exécuter | CI à exécuter |
| Linux ARM64 musl | Alpine 3.23 sur ARM64 natif | CI à exécuter | CI à exécuter |
| macOS x64 | macOS 15 Intel | CI à exécuter | CI à exécuter |
| macOS ARM64 | macOS 14 ARM64 | CI à exécuter | CI à exécuter |
| Windows x64 | Windows Server 2022 | CI à exécuter | CI à exécuter |

Les résultats locaux sont consignés dans `dist/<plateforme>/runtime-node22.json` et `runtime-node24.json`, avec les empreintes des archives et des sources correspondantes. Les anciennes exécutions de la version utilisant des dépendances cryptographiques ne valident pas cette réécriture : consulter `docs/VALIDATION.md` et les rapports liés à l'artefact exact. Les binaires GNU produits en CI sont construits sur glibc 2.35 ; la cible macOS de compilation est 11.0. Les autres architectures ne bénéficient d'aucune garantie tant que leurs véritables exécutions n'ont pas réussi. La présence d'une ligne de workflow ne prouve pas cette réussite.

Le workflow `.github/workflows/ci.yml` exécute formatage, Clippy, tests Rust/Node, vérification des vecteurs NIST, contrôle du graphe de production, audit des seuls outils de développement, échanges avec un OpenSSL indépendant et fuzzing avec instrumentation ASan. OpenSSL 3.5.8 est compilé à partir d'une archive officielle vérifiée par SHA-256 et utilisé seulement par les tests. Chaque cible construit un binaire une seule fois puis teste les mêmes archives sous Node.js 22 et 24. Les images Alpine et les actions GitHub sont référencées par empreinte.

Après collecte des sept dossiers `dist/<plateforme>/`, `npm run verify:release` exige un checkout de compilation propre et commité, des commits identiques, les bonnes versions, les empreintes attendues et une preuve de test des archives sous chaque version de Node.js. Une preuve manquante ou périmée fait échouer le contrôle. Le workflow produit alors `release-verification.json` et, hors pull request, une attestation GitHub de provenance des archives. Les métadonnées locales non signées ne remplacent pas cette attestation.

Le workflow GitHub est activé lors de la publication du dépôt. Un résultat n'est déclaré validé qu'après exécution réussie de la cellule correspondante ; la seule présence du workflow ne suffit pas.

`verify:release` refuse une livraison multiplateforme tant que les sources ne sont pas commitées et que les preuves d'exécution de la matrice ne sont pas disponibles. Les artefacts de développement restent utilisables pour les tests locaux.
