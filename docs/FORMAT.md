# Format binaire PQRS, version 1

Tous les entiers sont non signés, en ordre little-endian. Les concaténations
ci-dessous sont littérales, sans séparateur implicite. Aucun JSON, base64,
terminateur nul ou transformation Unicode ne participe à la cryptographie.

Chaque objet commence par cet en-tête de 10 octets :

| Position | Taille | Valeur |
| --- | --- | --- |
| 0 | 4 | ASCII `PQRS` (50 51 52 53 en hexadécimal) |
| 4 | 1 | Version `01` |
| 5 | 1 | Type ci-dessous |
| 6 | 4 | Longueur exacte de la charge utile, hors en-tête |

Les octets supplémentaires, versions inconnues, types incorrects et tailles
incohérentes sont refusés. Il n'existe aucun repli vers un ancien algorithme.

| Type | Objet | Charge utile |
| --- | --- | --- |
| 1 | Clé publique de chiffrement | 1 568 octets ML-KEM-1024 `ek` |
| 2 | Clé privée de chiffrement | Graine de 64 octets `d || z`, FIPS 203 |
| 3 | Clé publique de signature | 2 592 octets ML-DSA-87 `pk` |
| 4 | Clé privée de signature | Graine de 32 octets `xi`, FIPS 204 |
| 16 | Message chiffré | 1 568 octets d'encapsulation, nonce de 12 octets, chiffré, tag de 16 octets |
| 32 | Signature | 4 627 octets de signature ML-DSA-87 |

Les graines privées sont la représentation canonique exportée, sans clé publique
supplémentaire. L'import reconstruit la clé et sa clé publique ; la représentation
étendue des clés privées FIPS n'est pas acceptée. Ces exports ne sont pas chiffrés.
Les clés publiques ML-KEM font l'objet de la vérification des coefficients exigée
par la primitive. Les clés publiques ML-DSA ont une représentation fixe dont tous
les champs de la bonne longueur sont décodables ; cela n'atteste pas leur identité.

## Chiffrement

Le texte clair et les données associées externes `aad` sont limités chacun à
16 777 216 octets. L'enveloppe a une surcharge exacte de 1 606 octets. Même un
message vide contient une encapsulation, un nonce et un tag complets.

1. Obtenir 32 octets aléatoires uniformes pour ML-KEM. Effectuer une nouvelle
   encapsulation ML-KEM-1024 et obtenir `(kem_ciphertext, shared_secret)`.
2. Obtenir un nouveau nonce de 12 octets depuis la source aléatoire du système.
3. Construire l'en-tête du type 16, dont la longueur vaut `1596 + message.len()`.
4. Définir `prefix = header || kem_ciphertext || nonce` (1 590 octets).
5. Dériver 32 octets avec HKDF-SHA-512 (RFC 5869) : `IKM = shared_secret`,
   `salt = ASCII("post-quantum/encryption/v1")`,
   `info = header || recipient_public_key_raw || kem_ciphertext || nonce`.
6. Chiffrer avec ChaCha20-Poly1305 (RFC 8439), clé dérivée et nonce ci-dessus.
   Les données authentifiées sont
   `prefix || uint64_le(aad.len()) || aad`.
7. Retourner `prefix || ciphertext || tag`.

Les données associées ne sont pas incluses dans l'enveloppe ; le destinataire doit
fournir exactement les mêmes octets. La dérivation lie la clé au destinataire et
au format ; l'authentification couvre l'intégralité de l'en-tête et de
l'encapsulation. ML-KEM utilise son rejet implicite standard : une encapsulation
altérée mène à une mauvaise clé et finalement à un échec d'authentification AEAD.
Aucun texte clair n'est retourné avant authentification. Le chiffrement ne
prouve pas l'identité de l'expéditeur.

## Signature

Le message est limité à 16 777 216 octets et le contexte externe à 255 octets.
Construire `signature_header` pour le type 32 et la longueur 4 627. Signer avec
**ML-DSA-87 pure, randomisée**, sans préhachage :

```
FIPS_context = ASCII("post-quantum/signature/v1")
M = signature_header || uint16_le(context.len()) || context || message
signature = ML-DSA.Sign(private_key, M, FIPS_context)
result = signature_header || signature
```

Le contexte d'application est encadré dans `M`, distinct du contexte FIPS fixe.
Une opération de signature demande 32 nouveaux octets aléatoires au système.
Le contexte n'est pas inclus dans la signature exportée et doit être connu du
vérificateur. Toute signature invalide ou malformée, y compris un en-tête inconnu,
renvoie `false`. Un message ou contexte dépassant les limites produit une erreur
d'utilisation. Aucune normalisation du message n'a lieu.

## Interopérabilité et stabilité

Les primitives correspondent à FIPS 203 et FIPS 204, paramètres de catégorie 5.
PQRS est un format propre à ce paquet, pas un format normalisé ou une construction
certifiée. Modifier le cadrage, une chaîne de domaine, les algorithmes ou leur
composition exige une nouvelle version du protocole. Les vecteurs officiels et
les fixtures d'interopérabilité du dépôt fixent les octets attendus ; les graines
qui y figurent sont publiques et ne doivent jamais être utilisées en production.
