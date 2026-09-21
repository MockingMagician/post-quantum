# Modèle de sécurité et revue interne

## Construction

Le cœur emploie ML-KEM-1024 (FIPS 203), ML-DSA-87 (FIPS 204), HKDF-SHA-512 et ChaCha20-Poly1305 (RFC 8439). Les primitives sont écrites localement d'après les normes ; leur [provenance](PROVENANCE.md), les corrections NIST examinées et les données de test sont documentées. Le lockfile de production ne contient que les trois crates locales. Il n'y a pas d'algorithme asymétrique classique supplémentaire ni de choix de suite par l'appelant.

La catégorie NIST 5 concerne les paramètres ML-KEM et ML-DSA. Elle ne signifie pas « 256 bits de sécurité quantique » pour l'ensemble du paquet. La construction symétrique utilise une clé de 256 bits et un tag de 128 bits, avec ses propres bornes de confidentialité et de falsification. Les niveaux de sécurité reposent sur les hypothèses actuelles des primitives, pas sur une preuve d'invulnérabilité.

Chaque chiffrement obtient 32 octets uniformes pour l'encapsulation ML-KEM et un nonce de 12 octets auprès du système. Une nouvelle clé de message est dérivée du secret encapsulé. La dérivation lie la version, la suite implicite, la longueur, la clé publique du destinataire, le ciphertext KEM et le nonce. Le tag couvre l'en-tête, le ciphertext KEM, le nonce et les données associées encadrées par leur longueur. Aucun nonce ni aléa de test n'est sélectionnable dans l'API publique.

Les signatures sont du ML-DSA pur randomisé. Le contexte FIPS fixe `post-quantum/signature/v1` sépare l'usage du protocole ; le message signé inclut l'en-tête de signature et le contexte applicatif encadré. Toute vérification porte sur les octets exacts, sans canonicalisation implicite de JSON ou Unicode. La composition propre au paquet est documentée dans `FORMAT.md` ; elle n'est pas un protocole standardisé ni formellement prouvé.

## Adversaires et limites

Le paquet vise un attaquant pouvant observer, modifier, remplacer et soumettre des messages, signatures et clés sérialisées. Le système d'exploitation, la source aléatoire, Node.js et le processus appelant sont supposés dignes de confiance. Une application peut soumettre des octets malformés ; le paquet les valide avant utilisation et borne les allocations par opération.

Les clés publiques sont authentifiées hors de ce paquet. Une clé remplacée par l'attaquant ne peut pas être distinguée d'une clé légitime par la cryptographie seule. L'application assume les identités, la révocation, les identifiants de message et la prévention du rejeu. Les erreurs d'authentification ne distinguent pas mauvaise clé, mauvais AAD et ciphertext modifié ; les erreurs de structure publique sont distinctes.

Hors garanties : vol de mémoire du processus, débogueur privilégié, crash dumps, swap, attaques physiques, injection de fautes, processus ou dépendances compromis, résistance démontrée aux canaux auxiliaires, déni de service illimité. La taille maximale borne chaque opération ; le service appelant doit limiter leur nombre simultané. Il n'existe pas de protection des anciens messages après compromission de la clé de déchiffrement.

## Traitement des secrets

- Le cœur interdit `unsafe`. Les clés privées n'implémentent ni `Clone` ni `Debug`. Les fonctions d'export rendent explicitement des octets secrets à l'appelant.
- Les fonctions aléatoires utilisent une source système faillible. Une erreur, y compris après remplissage partiel, remonte sans génération ou signature de secours. Des tests injectent ces échecs pour la génération, l'encapsulation et la signature.
- La couche locale `post-quantum-platform` efface les buffers sensibles avec des écritures volatiles et une barrière de compilation. Les graines, secrets KEM, clés dérivées et tampons sensibles possédés par notre code utilisent son garde `Zeroizing`. Le tampon de déchiffrement est effacé sur échec ; aucun texte clair partiel n'est retourné.
- Les clés privées Node sont détenues par Rust derrière un verrou ; destruction et opérations concurrentes ne provoquent pas de libération prématurée. Les opérations déjà commencées peuvent terminer ; les nouveaux accès après révocation échouent. Attendre `destroy()` pour la fin de l'effacement détenu par l'objet.
- Les entrées Node sont inspectées et copiées sur le thread JS. Les vues partagées et détachées sont rejetées. Aucun buffer JS ni pointeur sur ses octets n'est transmis au worker. Les getters d'options s'exécutent avant inspection des autres buffers pour empêcher l'utilisation d'un pointeur invalidé par réentrance.
- Le binding Node contient les appels FFI locaux, la gestion explicite des références, travaux asynchrones, tags de type et callbacks de finalisation. L'inspection des entrées exige une vue validée : type Uint8Array, ArrayBuffer non partagé et non détaché, taille bornée, pointeur non nul. Aucun appel à du JavaScript n'intervient entre inspection et copie. Les codes de retour Node-API sont vérifiés.
- Les erreurs sont converties sur le thread JS ; les paniques Rust récupérables d'une tâche sont interceptées. Cela ne protège pas d'un arrêt du processus, d'une panne mémoire ou d'un bogue dans Node-API.

L'effacement est **au mieux** : les copies dans les registres, temporaires du compilateur créés lors de transformations optimisées ne sont pas toutes contrôlables. Les sorties et exports sont copiés vers des buffers Node ; aucune promesse d'effacement global de la mémoire JavaScript n'est faite. Aucune mémoire verrouillée contre le swap n'est utilisée.

## Assurance et références

La conformité de vecteurs, les échanges avec OpenSSL et le fuzzing sont des preuves de comportements observés. Ils ne constituent pas un audit, une preuve de sécurité de composition ou une preuve de temps constant. Le code doit être maintenu et réévalué avec les nouvelles analyses cryptographiques, les changements de compilateur et les avis sur les outils. Les tests de temps recherchent des signaux dans des scénarios bornés ; leur absence n'est pas une preuve de temps constant. La durée du rejet probabiliste de ML-DSA n'est pas constante par construction.

- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
- [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439)
- [Provenance de la réécriture et base de confiance](PROVENANCE.md)
