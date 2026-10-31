# 0001 — Format des ADR

- Statut : Accepté
- Date : 2026-10-31
- Lot : T00

## Contexte

Le projet est construit par lots successifs, souvent par des sessions de travail sans
mémoire commune. Une décision qui n'est pas écrite est rediscutée, ou contredite sans le
savoir.

## Décision

- Toute décision structurante (dépendance, écart à `specs/architecture.md`, choix de
  conception qui engage plusieurs lots, règle de sécurité) donne un ADR dans `docs/adr/`,
  dans le commit qui l'applique, avec la mise à jour d'`architecture.md` si besoin.
- Fichier `NNNN-sujet.md`, numéroté à la suite, en français, selon le gabarit `0000` :
  Contexte, Décision, Conséquences, Alternatives écartées.
- Un ADR accepté n'est pas réécrit (corrections de forme exceptées) ; on le remplace par
  un nouvel ADR et on change son statut en « Remplacé par NNNN ».
- L'index `docs/adr/README.md` liste tous les ADR et leur statut.

## Conséquences

Chaque fiche de lot cite dans son Journal les ADR créés. La relecture d'un lot vérifie
qu'aucune décision structurante n'est restée implicite.

## Alternatives écartées

- Décisions dans les seules fiches de lot : dispersées, et une fiche décrit un lot, pas la
  durée de vie d'une décision.
- Format MADR complet : plus lourd sans bénéfice à cette échelle.
