# post-quantum

Chiffrement ML-KEM-1024 / HKDF-SHA-512 / ChaCha20-Poly1305 et signatures ML-DSA-87, implémentés en Rust et exposés à Node.js par un module natif. L'API Rust est utilisable indépendamment de Node.js.

**Validation interne, sans audit indépendant ni certification FIPS.** Les paramètres asymétriques appartiennent à la catégorie NIST 5 ; cette catégorie ne constitue pas une preuve de sécurité du paquet ou de sa composition. Les primitives et le binding Node-API sont écrits localement d'après les normes, sans crate tierce dans la compilation de production. Cette réécriture n'a pas fait l'objet d'un audit indépendant ; consulter la [provenance](docs/PROVENANCE.md). Voir le [modèle de sécurité](docs/SECURITY.md) et les [preuves de validation et limites](docs/VALIDATION.md).

Le paquet reste privé. La publication npm et la licence de diffusion ne sont pas définies à cette étape. Les archives locales peuvent être installées ensemble ; aucun compilateur n'est nécessaire chez leur utilisateur.

## Développement

Prérequis : Rust 1.93.1 et Node.js 22 ou 24. Les scripts de compilation n'ont aucune dépendance JavaScript : aucune installation npm préalable n'est requise. Depuis la racine :

```sh
npm run build
npm test
cargo test --workspace --frozen
node validation/production_graph.mjs
```

`npm run build` compile le cœur et la couche Node avec Cargo, puis copie le module dans `native/`. Il n'existe aucune implémentation cryptographique JavaScript de secours. Les types TypeScript sont fournis ; une application TypeScript doit disposer de ses types Node.js (`@types/node`).

## Utilisation

```js
import {
  generateEncryptionKeyPair, generateSigningKeyPair,
  encrypt, decrypt, sign, verify,
} from 'post-quantum';

const recipient = await generateEncryptionKeyPair();
const author = await generateSigningKeyPair();
const message = Buffer.from('Bonjour', 'utf8');
const aad = Buffer.from('mon-application/message/42');
const context = Buffer.from('mon-application/signature/v1');

try {
  const encrypted = await encrypt(recipient.publicKey, message, { aad });
  const plaintext = await decrypt(recipient.privateKey, encrypted, { aad });
  const signature = await sign(author.privateKey, message, { context });
  const authentic = await verify(author.publicKey, plaintext, signature, { context });
  if (!authentic) throw new Error('Signature invalide');
} finally {
  await Promise.all([recipient.privateKey.destroy(), author.privateKey.destroy()]);
}
```

CommonJS expose les mêmes fonctions : `const pq = require('post-quantum')`. L'[exemple complet](examples/signed-message.mjs) signe le message et son destinataire, chiffre le message accompagné de sa signature, puis vérifie avant de rendre son contenu à l'application. Il inclut le contexte applicatif et refuse les cadres incomplets.

## Contrat de l'API

Toutes les fonctions de génération, d'import, de chiffrement et de signature renvoient des promesses. La cryptographie s'exécute dans le pool de travail libuv. Les arguments sont copiés avant retour de l'appel ; ces copies, bornées, restent un coût sur le thread JavaScript. Prévoir une limite applicative de concurrence et de débit.

- Entrées : uniquement `Uint8Array` et `Buffer`, jamais une chaîne ou un objet sérialisé implicitement. Les vues sur `SharedArrayBuffer` et les buffers détachés sont rejetés.
- Messages : de 0 à **16 Mio**. Données associées `aad` : de 0 à 16 Mio. Contexte de signature : de 0 à 255 octets. Pas de streaming.
- `aad` et `context` ne sont pas embarqués : les deux parties doivent fournir exactement les mêmes octets. Les valeurs omises valent un tableau vide.
- `verify()` renvoie `false` pour une signature incorrecte, tronquée, de version inconnue ou de mauvaise longueur. Une erreur d'utilisation ou une limite dépassée est signalée par une erreur.
- Le déchiffrement ne renvoie du texte clair qu'après authentification. Une clé incorrecte ou une altération cryptographique produit `ERR_AUTHENTICATION_FAILED`. Les erreurs de format public peuvent avoir un code distinct.
- Les classes ne peuvent pas être construites directement ; utiliser `generateEncryptionKeyPair()`, `generateSigningKeyPair()` ou `importEncryptionPublicKey()`, `importEncryptionPrivateKey()`, `importSigningPublicKey()`, `importSigningPrivateKey()`.
- `key.export()` renvoie le format binaire versionné, et **expose un secret** pour une clé privée. L'application doit protéger cet export, limiter ses copies et effacer son buffer lorsqu'il n'est plus utile. Le paquet ne stocke aucune clé.
- `privateKey.destroy()` révoque immédiatement les nouveaux accès ; sa promesse se résout après libération du verrou et effacement des données privées détenues. Une opération ayant déjà acquis la clé peut terminer. L'appel est idempotent ; `destroyed` indique la révocation. La collecte automatique libère aussi la clé, à un moment non déterministe.

Les erreurs applicatives portent les codes déclarés dans [index.d.ts](index.d.ts). Les erreurs de type au niveau Node-API (par exemple une clé d'une autre classe ou un argument manquant) peuvent être levées synchroniquement avec le code `ERR_INVALID_ARGUMENT`. Encadrer l'appel et son `await` dans le même `try/catch`. Ni messages ni secrets ne sont inclus dans les erreurs applicatives.

## Garanties et responsabilités

Une signature démontre la possession de la clé privée correspondante. L'application doit authentifier la clé publique, vérifier l'identité attendue et gérer rotation, révocation, rejeu et stockage. Le chiffrement seul n'authentifie pas l'expéditeur. La compromission ultérieure d'une clé destinataire permet de déchiffrer ses messages enregistrés ; aucun protocole de confidentialité persistante n'est fourni.

Le format propre au paquet est spécifié dans [FORMAT.md](docs/FORMAT.md), avec [vecteur de compatibilité](validation/vectors/protocol-v1.json). Ne jamais utiliser les clés publiques de test comme secrets réels.

## Distribution et vérification

Les cibles prévues sont Linux x64/ARM64 (glibc et musl), macOS x64/ARM64, Windows x64 ; Node.js 22 et 24. Les [résultats de validation](docs/VALIDATION.md) distinguent les cibles exécutées localement de celles en attente de CI. À la demande du propriétaire, cette étape comprend la préparation de la CI uniquement, sans envoi sur GitHub ni exécution distante. Une future livraison multiplateforme restera conditionnée à la validation de toute la matrice.

```sh
npm run pack:artifacts
npm run test:package
node scripts/benchmark.mjs --iterations 30
```

Les archives racine et plateforme, empreintes SHA-256 et métadonnées de compilation sont préparées dans `dist/<plateforme>/`. Le workflow est configuré pour vérifier les archives installées avec les deux versions Node, l’absence de dépendances tierces de production, les dépendances des outils, les vecteurs NIST, l'interopérabilité et le fuzzing. Il ne publie rien sur npm. Voir [BUILD.md](docs/BUILD.md) pour la matrice et les commandes de livraison.
