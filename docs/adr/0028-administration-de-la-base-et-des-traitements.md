# 0028 — Administration de l'instance : import d'une archive par PostgreSQL, état des instances, purge, traitements en échec

- Statut : Accepté
- Date : 2026-10-31
- Lot : T11

## Contexte

T06 a livré `vuln.Checker.Import(path)`, qui installe une archive locale, sans écran : un
site isolé n'avait pas d'autre moyen qu'un miroir de la liste. T11 doit ajouter l'import
manuel, l'état de la base « par instance », la purge des archives non cibles (écart de
T06) et l'écran des traitements en échec (`jobs.ListDead`, `Retry`, `Discard`, prêts depuis
T02).

Contraintes : l'archive pèse environ 200 Mio (`vulndb.max_archive_mib` : 2 Gio) ; son
installation prend plusieurs minutes et ne prend pas de contexte (ADR 0017) ; l'instance
web qui reçoit le fichier n'est pas forcément une instance worker (`workers.enabled`) ni
la même machine ; la base est la seule source de vérité (§ 1) ; aucune transaction ne
traverse un appel réseau (§ 7) ; le corps d'un formulaire est borné à 64 Kio avant CSRF ;
csrfx lit le jeton par `PostFormValue`, qui, sur un corps multipart, écrit tout fichier de
plus de 32 Mio sur le disque **avant** la vérification du jeton et avant la garde
d'administration (placée sur le groupe `/admin`, après CSRF).

## Décision

- **Téléversement en flux vers PostgreSQL** : pour la seule requête
  `POST /admin/vulndb/import`, un middleware `uploadGate`, placé après le chargement du
  visiteur et avant CSRF :
  - n'élargit la borne du corps (`max_archive_mib` + 64 Kio) qu'à un administrateur
    d'instance authentifié ; tout autre compte garde 64 Kio et reçoit le 404 de la garde ;
  - lit la première partie du formulaire, qui doit être `csrf_token` (le gabarit la place
    avant le fichier ; le navigateur envoie les champs dans l'ordre du document), et la
    présente à csrfx dans l'en-tête `X-CSRF-Token` qu'il accepte : la vérification reste
    celle de csrfx (égalité avec le cookie, en temps constant) ; un jeton absent ou placé
    après le fichier donne 403, sans rien lire du fichier ;
  - repousse les délais de lecture et d'écriture de la connexion à
    `vulndb.download_timeout`.
  Le handler lit la partie `archive` en flux et la range par blocs de 8 Mio
  (`vulndb_imports`, `vulndb_import_chunks`, migration 014), **un bloc par transaction** ;
  une dernière transaction déclare l'import complet (taille, SHA-256), met en file le job
  `vulndb.import` (priorité haute, 3 tentatives) et journalise la demande.
- **Installation par un job** : `vulndb.import` recopie les blocs dans un fichier
  temporaire de `vulndb.dir` (somme revérifiée), appelle `Checker.Import`, puis termine
  l'import (`done` avec l'archive, ou `failed` avec l'erreur), supprime les blocs et
  journalise l'issue, dans une transaction. Une archive invalide (`ErrInvalidArchive`,
  nouvelle erreur posée par `Checker` sur un échec d'installation ou un fichier vide),
  une somme fausse ou une taille excessive sont refusées sans nouvel essai ; une autre
  erreur est réessayée et la dernière tentative termine l'import en échec. Idempotent.
  L'archive importée devient la cible **même si elle est plus ancienne** que la cible
  actuelle : c'est le retour arrière volontaire d'un exploitant, annoncé sur l'écran.
- **Un seul import en cours** (index unique partiel sur `uploading`, `queued`) : un import
  bloqué (téléversement sans écriture depuis `vulndb.download_timeout`, ou en file sans
  job actif, par exemple abandonné depuis l'écran des traitements) est déclaré échoué au
  téléversement suivant.
- **État par instance** : chaque `vuln.Manager` rapporte, après chaque synchronisation,
  la version chargée et sa dernière erreur dans `vulndb_instances` (une ligne par
  instance, nommée comme la colonne `worker` de `jobs` : hôte et PID), la retire à l'arrêt
  propre ; les lignes sans nouvelles depuis 7 jours sont supprimées. L'écran classe chaque
  instance : à jour, en retard, sans base, sans nouvelles (au-delà de trois
  `sync_interval`, 15 min au moins pour ne pas signaler une première installation).
- **Purge** : `vuln.PurgeArchives` supprime toutes les archives qui ne sont pas la cible,
  dans une transaction qui verrouille d'abord `vulndb_state` (une cible fixée en même
  temps attend) ; demandée par un formulaire avec case de confirmation, journalisée. Ni
  les constats ni `vulndb_instances` n'ont de clé étrangère vers les archives.
- **Traitements en échec** : écran `/admin/jobs` (compteurs de la file, jobs morts
  paginés avec organisation, tentatives et dernière erreur) ; relance et abandon par
  `POST`, CSRF, dans une transaction qui verrouille le job (`jobs.GetDead … FOR UPDATE`),
  applique l'action et écrit l'entrée d'audit d'instance. L'organisation d'un job est lue
  sous sa propre RLS (`org.Service.Get`), sans nouvelle fonction `crossorg`.
- Nouvelles actions d'audit : `job.retried`, `job.discarded`, `vulndb.import_requested`,
  `vulndb.imported`, `vulndb.import_failed`, `vulndb.archives_purged`.

## Conséquences

- Une instance purement web suffit pour recevoir une archive ; il faut au moins une
  instance à workers pour l'installer (déjà nécessaire pour analyser).
- PostgreSQL porte temporairement l'archive deux fois (blocs d'import, puis archive) ; les
  blocs d'import sont supprimés à la fin de l'import, réussi ou non.
- Un mandataire inverse doit accepter un corps de `max_archive_mib` et la durée du
  téléversement (`docs/operations.md`).
- La route de téléversement est la seule dont le jeton CSRF n'est pas lu par csrfx dans le
  corps : l'ordre des champs du formulaire fait partie du contrat (testé).

## Alternatives écartées

- **Fichier temporaire sur l'instance web, chemin passé au job** : la machine qui exécute
  le job n'a pas ce disque (instances séparées) et l'état ne survit pas à un redémarrage.
- **Laisser csrfx analyser le formulaire** (`ParseMultipartForm`) : écrit le fichier dans
  le répertoire temporaire avant toute vérification, pour n'importe quel compte connecté,
  et le serveur ne supprime que les fichiers du formulaire de la requête d'origine, pas
  ceux d'une copie (`WithContext`) analysée par un middleware.
- **Une transaction pour tout le téléversement** : tiendrait une transaction ouverte
  pendant toute la durée d'un envoi réseau.
- **Installation dans la requête** : plusieurs minutes, sans contexte, sur une instance
  qui n'a peut-être pas de répertoire de base.
- **Refuser une archive plus ancienne que la cible** : priverait l'exploitant du retour
  arrière ; l'écran l'annonce et le journal d'audit trace l'opération.
- **Garder la dernière archive précédente à la purge** : un retour arrière reste possible
  par import ; « tout sauf la cible » est la règle la plus simple à vérifier.
