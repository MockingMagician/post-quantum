# Preuves ciblées et frontière native

Cette note décrit les obligations vérifiées sur le code du dépôt. Elle ne constitue ni un audit indépendant, ni une preuve de la composition du protocole, ni une garantie générale de temps constant.

## Propriétés Kani

Kani 0.66.0 est un **outil de développement**, absent du graphe de production. `cargo kani -p post-quantum-core --output-format terse` exécute les trois harnesses de `crates/core/src/arithmetic.rs`. La CI exécute la même commande avec la version de Kani épinglée.

Exécution locale du 25 septembre 2026 : **3 harnesses vérifiés sur 3**, aucune propriété échouée, et les quatre propriétés de couverture satisfaites. Le résultat doit être reproduit sur le commit publié par la CI.

| Harness | Domaine symbolique | Propriété |
| --- | --- | --- |
| `ml_kem_field_3329` | `0 ≤ a,b < 3329`, `0 ≤ x < 6658` | `reduce_once`, `add` et `sub` correspondent au calcul modulo 3329 ; `centered` et `from_centered` correspondent à la représentation signée canonique. |
| `ml_dsa_field_8380417` | `0 ≤ a,b < 8380417`, `0 ≤ x < 16760834` | Les mêmes propriétés modulo 8380417. |
| `implicit_rejection_byte_selection` | Tous les octets de rejet et d'acceptation ; masque égal à `0` ou `255` | La fonction réellement appelée par ML-KEM choisit l'octet du rejet pour `0` et celui de l'acceptation pour `255`. |

Des `kani::cover!` vérifient que les contraintes autorisent des bornes du domaine ainsi que les deux valeurs du masque. Kani vérifie aussi les débordements et les paniques sur ces chemins. Ces preuves ne couvrent pas `mul`, les NTT, les codecs complets, la génération du masque à partir du ciphertext, les 32 tours de sélection ensemble, ni le code machine optimisé. Les vecteurs ACVP et les tests indépendants restent nécessaires pour ces composants. Une preuve en échec ou interrompue par manque de ressources reste une obligation **non démontrée**.

## Revue interne de la frontière Node-API

Les appels Node-API et les pointeurs opaques sont concentrés dans `crates/node/src/ffi.rs` et `runtime.rs`. Les obligations de propriété relues sont :

| Frontière | Invariant attendu | Validation associée |
| --- | --- | --- |
| État par environnement | `Box<Rc<EnvState>>` transféré à Node après `napi_set_instance_data`; finalizer ou chemin d'échec le libère une seule fois. `Rc`/`Cell` restent sur le thread principal. | Arrêt de Worker, GC, compteurs de ressources des hooks de validation. |
| Entrées JS | Le pointeur de `Uint8Array` est copié avant de rendre la main à JavaScript ; les buffers détachés ou partagés sont rejetés. Aucune vue empruntée ne traverse le job asynchrone. | Vues, détachement, getters réentrants, limites de taille. |
| Clés | `napi_wrap` acquiert le `Box<KeyHandle>` seulement en cas de succès ; le tag de type et le genre sont contrôlés avant `napi_unwrap`. | Contrefaçon de prototype, types croisés, destruction et GC. |
| Travail asynchrone | Le `Box<Job>` passe au callback de fin seulement après une mise en file réussie. Le worker ne touche qu'à `Compute: Mutex<_>` ; le callback de fin récupère la propriété puis supprime la tâche et ses références. | Échecs injectés à chaque étape, panique du worker, ASan, terminaison de Worker. |
| Arrêt | Le hook marque l'environnement fermé, annule les tâches en attente et attend que les callbacks de fin vident le registre avant de retirer le hook. | Terminaison de Workers avec opérations en vol. |

Cette revue est **interne et limitée** : la conformité des signatures C Node-API, les garanties de l'hôte Node/V8 et tous les interleavings possibles ne sont pas prouvés par Kani ou ASan. Les binaires d'ASan instrumentent le Rust, pas Node ni la bibliothèque standard Rust. Un audit externe devra reprendre ces obligations et tester des environnements supplémentaires.

## Code compilé

`node validation/codegen.mjs --target x86_64-unknown-linux-gnu`, sa variante ARM64, et `python3 validation/linked_codegen.py` capturent et filtrent les séquences documentées dans [CODEGEN.md](CODEGEN.md). Les sorties sont liées au compilateur, à la cible et à l'empreinte source. Les filtres détectent certains motifs indésirables ; une lecture humaine du binaire livré reste nécessaire après chaque changement de compilateur, cible ou code sensible. L'absence de motif n'est pas une preuve de temps constant.

Sur le binaire Linux x64 compilé localement avec Rust 1.93.1, la séquence de sélection observée après le masque de rejet utilise des opérations SIMD `pand`/`por`, sans branche conditionnelle sur ce masque dans cette séquence. Le contrôle d'empreintes relie les extraits au module natif. Cela ne caractérise pas les chemins restants, les autres cibles ou les effets microarchitecturaux.
