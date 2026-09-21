# Politique de sécurité

Ce projet effectue une validation interne. Il n'a pas fait l'objet d'un audit indépendant, n'est pas certifié FIPS et ne revendique pas de preuve absolue de résistance quantique. Les implémentations ML-KEM, ML-DSA, primitives symétriques et binding Node-API sont locales ; leur réécriture exige sa propre validation et n’est pas couverte par les contrôles effectués sur une bibliothèque tierce.

Le [modèle de menace et la revue des secrets](docs/SECURITY.md) décrivent les garanties visées. Le [rapport de validation](docs/VALIDATION.md) identifie les contrôles exécutés et ceux encore nécessaires.

## Signalement

Aucun canal public de divulgation n'est encore configuré pour ce dépôt privé. Transmettre un signalement directement au propriétaire du dépôt par un canal privé déjà établi, sans clé de production ni donnée confidentielle. Une publication publique nécessite auparavant la désignation d'un contact de sécurité et d'une politique de versions prises en charge.

Joindre la version ou l'empreinte du code, la plateforme, les versions Node/Rust, le scénario et un exemple minimal utilisant des données synthétiques. Les rapports seront évalués avant une diffusion publique des détails. Aucun engagement de délai de correction n'est annoncé à ce stade.

## Conditions de livraison

La production ne compile aucune crate tierce ; ce fait est vérifié avec cache vide et réseau isolé. Les outils de développement sont séparés et verrouillés, et leurs avis de sécurité sont contrôlés ; une vulnérabilité non résolue ou une anomalie de sécurité bloque la livraison. Toute correction cryptographique ou de format doit repasser la conformité, l'interopérabilité, le fuzzing et les tests de plateformes concernés. Un changement de format impose une nouvelle version de protocole, sans repli silencieux.
