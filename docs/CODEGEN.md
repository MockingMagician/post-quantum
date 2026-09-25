# Revue ciblée du code optimisé

Les expressions Rust sans branchement ne garantissent pas que le compilateur
produira un code sans branchement. La réécriture a donné deux exemples concrets
avec Rust 1.93.1 sur Linux x64 :

- La sélection masquée du secret ML-KEM était transformée en copie conditionnelle
  selon la validité de l'encapsulation.
- La comparaison XOR/OR du tag AEAD était transformée en comparaisons successives
  avec retour anticipé au premier octet différent.

La frontière locale `post_quantum_platform::opaque_u8` empêche ces transformations
observées : une lecture volatile non intégrée empêche la propagation de la valeur
complète de réduction ou du masque. La comparaison consomme le résultat XOR/OR
complet avant sa conversion en booléen, et la sélection reçoit un masque opaque.
Il ne s'agit pas d'une garantie de temps constant fournie par le langage Rust.

## Reproduction

Installer d'abord la toolchain épinglée et ses bibliothèques standard pour la
cible ; aucune crate tierce n'est nécessaire. Puis :

```sh
node validation/codegen.mjs --target x86_64-unknown-linux-gnu
node validation/codegen.mjs --target aarch64-unknown-linux-gnu
```

Les assembleurs, commandes, empreintes et résultats du contrôle d'instructions
sont conservés sous `.reports/codegen/`. Le script vérifie l'absence des appels de
comparaison et divisions entières surveillés, ainsi que la présence de la
frontière opaque. Ce filtrage ne remplace pas une lecture de l'assembleur : des
branchements, adresses mémoire ou instructions problématiques peuvent lui échapper.

## Périmètre de lecture

La lecture ciblée des chemins corrigés sur x64 et ARM64 vérifie :

- comparaison complète des encapsulations, calcul des deux secrets ML-KEM puis
  sélection par masques sans branchement sur le résultat de comparaison ;
- réduction complète des 16 octets de tag avant la décision d'authentification ;
- accumulation des normes ML-DSA sans arrêt sur un coefficient secret ;
- sélection de la réduction Poly1305 par masques ;
- instructions arithmétiques et parcours de tableaux des transformations NTT,
  SHA-512 et Keccak dans le périmètre examiné.

Les assembleurs produits par ce script proviennent des bibliothèques Rust avant
le dernier passage ThinLTO et l'édition de liens Node. Ils ne doivent pas être
présentés comme une preuve portant sur tous les binaires distribués. Toute revue
complémentaire des objets finaux doit conserver ses propres commandes et
empreintes. Refaire la vérification lors d'un changement de compilateur,
d'optimisations, de cible ou de code sensible.

Les boucles de rejet de ML-DSA restent probabilistes. Ni cette lecture, ni une
campagne statistique sans signal ne prouvent l'absence de canaux auxiliaires.

## Objets Node après ThinLTO, Linux x64

```sh
python3 validation/linked_codegen.py
```

Ce contrôle nécessite Python 3, GNU `objdump` et la toolchain Rust épinglée sur
Linux GNU x64. Il compile le module Node avec le profil `release` habituel et
`-C save-temps=yes`, dans un répertoire temporaire isolé. Il conserve ensuite
les objets natifs après ThinLTO, leur désassemblage, la bibliothèque liée et le
rapport `artifacts/validation/linked-codegen.json`. Les sources Cargo/Rust sont
empreintées avant et après la compilation ; elles doivent rester identiques.
Le parseur accepte le nom démanglé de `symmetric::tag` ou son symbole Rust exact
avec suffixe LLVM, selon la version d'`objdump` du runner ; cette fonction reste
obligatoire et ses octets doivent être retrouvés dans la bibliothèque liée.

La capture sélectionne `opaque_u8`, la comparaison des octets, la décapsulation
ML-KEM, les normes ML-DSA, le calcul du tag et son contrôle. Des suites d'octets
sans relocation, issues de ces fonctions, sont recherchées exactement dans la
bibliothèque liée. Leurs empreintes et positions figurent dans le rapport. Une
modification de l'organisation des fonctions ou une corrélation manquante fait
échouer la capture et demande une nouvelle inspection ; ce n'est pas
automatiquement une vulnérabilité.

La lecture ciblée initiale des objets finaux Rust 1.93.1 x64 retrouve la sélection
KEM par `pand`/`por`, la réduction SIMD des 16 octets du tag avant la décision,
les normes SIMD sur tous les coefficients et la réduction Poly1305 par masques.
La frontière opaque reste une écriture, une lecture et un effacement de son
octet local. La présence des extraits dans le binaire confirme la portée de
cette lecture ; elle ne prouve pas la sécurité de toutes les instructions.
Des divisions de longueurs publiques peuvent subsister dans des auxiliaires
d'itération de la bibliothèque standard après ThinLTO.

`captureAndCorrelationPassed` signifie uniquement que la capture et la
corrélation ont réussi. Le script ne décide pas si les branchements restants
portent sur des secrets et n'attribue aucune preuve de temps constant. Relire
les désassemblages après tout changement pertinent ; ARM64 final, macOS,
Windows et les autres configurations nécessitent leurs propres vérifications.
