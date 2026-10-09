# Mesh — Trouver un audit indépendant sans frais pour l’association

Brief destiné à la personne chargée des premiers contacts. Préparé le 29 septembre 2026 ; pistes vérifiées sur les sites officiels à cette date.

**Ta mission : trouver une équipe compétente et une prise en charge de l’audit de notre bibliothèque postquantique, avant son intégration à Mesh.** Tu n’as pas besoin de savoir lire le code : tu présentes la démarche, identifies les possibilités et organises un échange avec notre responsable technique.

À utiliser avec les [messages prêts à adapter](AUDIT-MESSAGES.md) et la [fiche à transmettre aux spécialistes](AUDIT-FICHE-TECHNIQUE.md).

## 1. Le projet, en mots simples

Mesh Network Association est une association française loi 1901. Elle développe et maintient Mesh, un réseau de messagerie décentralisé : les messages circulent par des relais et sont chiffrés de bout en bout, c’est-à-dire rendus illisibles entre l’appareil de départ et celui du destinataire. C’est la mission présentée sur le [site de l’association](https://www.mesh-network.org/).

Nous préparons une future évolution de son chiffrement. Le projet à examiner est une **bibliothèque**, un ensemble de fonctions logicielles réutilisables par d’autres programmes. Elle sert à chiffrer des messages et à créer des signatures numériques.

Quelques mots utiles :

| Mot | Ce qu’il faut comprendre |
| --- | --- |
| Chiffrement | Rend un message illisible sans la clé nécessaire pour le déchiffrer. |
| Signature numérique | Permet de vérifier qu’un message n’a pas été modifié et qu’il a été signé avec la clé attendue. Associer cette clé à une personne reste une autre étape. |
| Postquantique | Désigne des méthodes conçues pour résister aussi aux attaques utilisant de futurs ordinateurs quantiques puissants. Elles fonctionnent sur des ordinateurs ordinaires. |
| Algorithme / implémentation | L’algorithme est la méthode ; l’implémentation est le code qui l’exécute. Une méthode reconnue peut être mal programmée. |
| Logiciel libre | Logiciel dont la licence autorise notamment l’étude, la modification et la redistribution. Cela ne signifie pas qu’il a été audité. |

**Nous utilisons des algorithmes standardisés, mais avons écrit notre propre implémentation et leur assemblage.** C’est cet ensemble qu’il faut examiner. Les tests internes sont documentés ; aucun audit indépendant ni certification n’a encore été obtenu. Les détails sont dans le [dossier technique](AUDIT.md).

Le site de Mesh décrit encore une solution appelée TweetNaCl. La bibliothèque postquantique est une évolution prévue, pas le chiffrement déjà déployé. La demande porte sur cette bibliothèque ; elle ne couvre pas à elle seule toute la messagerie, les relais ou les autres projets de l’association.

## 2. Ce que nous cherchons

Un audit est un examen délimité par des spécialistes indépendants : ils lisent le code, analysent sa conception et recherchent des défauts. Nous souhaitons un rapport écrit indiquant les problèmes, leur gravité, les corrections proposées et ce qui a réellement été examiné, puis une vérification des corrections.

| Proposition reçue | Comment la considérer |
| --- | --- |
| Audit spécialisé avec périmètre et rapport | Objectif principal, si son financement est assuré. |
| Revue ciblée par un chercheur ou un expert | Première étape utile ; préciser les parties examinées et celles restant à auditer. |
| Scan automatique ou avis informel | Peut aider à préparer le travail, mais ne remplace pas une revue cryptographique. |
| Certification | Démarche distincte, qui n’est pas l’objet de cette demande. |

« Sans frais pour l’association » peut signifier du travail offert, un audit payé par un mécène ou une prise en charge par un programme de soutien. **Le statut associatif ne donne pas automatiquement droit à un audit gratuit.** Même financé, l’audit demandera du temps à notre équipe pour répondre et corriger le code.

L’argumentaire : protection de la confidentialité des communications, bibliothèque sous licences libres MIT/Apache-2.0 pouvant être réutilisée, démarche avant intégration, documentation déjà préparée. Ne pas présenter le logiciel comme inviolable, certifié ou déjà validé par un organisme extérieur. Un audit apporte des éléments de confiance sur un périmètre précis, pas une garantie absolue.

## 3. Les pistes, dans l’ordre conseillé

Cet ordre est une recommandation de prospection, pas une estimation des chances d’acceptation. Les compétences ou dispositifs ci-dessous sont documentés ; leur disponibilité pour Mesh et la gratuité restent à confirmer.

| Priorité / organisme | Pourquoi cette piste | Première action concrète |
| --- | --- | --- |
| **1 — OSTIF** | Organise des audits de logiciels libres et indique aider des projets à trouver des sponsors couvrant tout ou partie du coût. | Utiliser le formulaire indiqué en bas de [Get an Audit](https://ostif.org/get-an-audit/). Demander un cadrage et une recherche de financement intégral pour une bibliothèque encore jeune. Écrire en anglais. |
| **1 — NLnet / Restack** | NLnet soutient les technologies ouvertes ; Restack annonce un soutien financier et des services dont des audits. | Poser la question du montage adapté via le [contact NLnet](https://nlnet.nl/contact/), puis préparer une candidature si pertinente. Le [premier appel Restack](https://nlnet.nl/restack/) annonce une clôture le **3 novembre 2026 à 12 h CET**, à revérifier avant dépôt. Écrire en anglais. |
| **2 — Quarkslab** | Cabinet disposant d’une [expertise en audit cryptographique, implémentations et fuites d’informations](https://www.quarkslab.com/expertises-cybersecurity-deep-security-research/). | Passer par le [contact officiel](https://www.quarkslab.com/contact-us/). Demander s’il existe une possibilité de mission offerte ou financée par un partenaire, éventuellement avec OSTIF. Aucun programme gratuit n’a été confirmé. Français possible. |
| **2 — Radically Open Security** | Cabinet se présentant comme non lucratif, proposant des [audits de code et de protocoles cryptographiques](https://www.radicallyopensecurity.com/services/). | Écrire à **info@radicallyopensecurity.com**, indiqué sur sa [page contact](https://www.radicallyopensecurity.com/contact/). Demander une prise en charge par un programme ou un soutien exceptionnel. Non lucratif ne signifie pas prestations gratuites. Anglais conseillé. |
| **3 — Inria, équipe CAPSULE** | Travaille sur la cryptographie postquantique et la sécurité des implémentations ; voir son [rapport d’activité 2025](https://radar.inria.fr/report/2025/capsule/index.html). | Rechercher l’interlocuteur approprié sur le [site d’équipe](https://team.inria.fr/capsule/) et proposer un échange exploratoire ou une revue ciblée. Le site d’équipe n’a pas pu être consulté automatiquement ; coordonnées à relever manuellement. Français possible. |
| **3 — Inria, équipe COSMIQ** | Recherche sur les algorithmes cryptographiques classiques et postquantiques ; [page officielle avec membres et contacts](https://www.paris.inria.fr/secret/index.html). | Passer par les liens de contact de l’équipe pour demander une orientation vers un spécialiste de ML-KEM/ML-DSA, ou l’intérêt pour une collaboration ciblée. Français possible. |

Pour NLnet, les [conditions générales de candidature](https://nlnet.nl/funding.html) demandent des résultats libres et ouverts ; chaque fonds a ses propres critères. Faire préciser si un projet de consolidation de la bibliothèque, avec audit et corrections, peut être soutenu. La licence de cette bibliothèque ne suffit pas à établir l’éligibilité de tout Mesh.

Pour les chercheurs, demander d’abord une orientation ou un intérêt scientifique. Une équipe universitaire n’est pas un service d’audit gratuit ; un travail étudiant éventuel doit être encadré et restera une revue au périmètre explicite.

## 4. Comment commencer et suivre les réponses

1. **Préparer l’envoi avec notre responsable technique :** obtenir son nom, son adresse, ses disponibilités, un lien de code accessible au destinataire et son accord sur les documents partageables. L’accès public au dépôt n’a pas pu être confirmé lors de cette préparation.
2. **Contacter OSTIF et NLnet**, puis les deux cabinets, avec les modèles adaptés. Joindre la fiche technique seulement si utile au premier échange. Demander un bref rendez-vous de cadrage.
3. **Solliciter les équipes de recherche** pour une revue ciblée ou une mise en relation. Adapter chaque message à leur domaine.
4. **Relancer une fois après 7 à 10 jours ouvrés**, sauf délai de réponse annoncé. En cas de refus, demander une autre piste.
5. **Transmettre toute proposition au responsable technique** pour évaluer sa couverture et l’effort demandé. Un premier succès est un interlocuteur qualifié et une voie de financement précise ; l’objectif final reste une mission cadrée et financée, avec rapport et revue des corrections.

Pendant un échange, noter les réponses à ces questions :

- Avez-vous une expérience des implémentations postquantiques, notamment ML-KEM/ML-DSA, et du Rust ? Qui couvrirait l’interface avec Node.js ?
- Quelle partie pourriez-vous examiner, et que laisseriez-vous hors périmètre ?
- Qui paierait la mission ? Resterait-il des frais ou des engagements pour l’association ?
- Quels seraient le calendrier, le rapport remis et le suivi des corrections ?
- Quel temps et quels documents attendez-vous de notre équipe ? Comment coordonner les corrections et la publication du rapport ?

À une question technique, répondre simplement : **« Je coordonne les premiers échanges ; je transmets ce point à notre responsable technique, qui pourra vous répondre précisément. »**

| Organisme / interlocuteur | Contacté le | Réponse et périmètre envisagé | Financement à confirmer | Prochaine action / date |
| --- | --- | --- | --- | --- |
| OSTIF | — | — | — | — |
| NLnet | — | — | — | — |
| Quarkslab | — | — | — | — |
| Radically Open Security | — | — | — | — |
| CAPSULE | — | — | — | — |
| COSMIQ | — | — | — | — |

Aucun organisme n’a été contacté dans le cadre de la préparation de ce brief.
