-- 017_ai_enrichment : enrichissement IA de l'agent dépôt (T12, ADR 0043).
--
-- Chaque projet porte son réglage d'enrichissement : « disabled » (défaut : aucun modèle
-- appelé), « local » (modèle local seulement) ou « external » (fournisseur externe
-- autorisé par un administrateur d'organisation). Chaque instantané garde le statut de
-- l'enrichissement déclaré par le SBOM (propriété lotor:enrichment des métadonnées) :
-- « complete », « incomplete » (budget ou erreur du fournisseur : composants de Syft
-- seuls), « carried » (commit intermédiaire d'un rattrapage, composants IA précédents
-- revérifiés et reportés), ou NULL sans enrichissement.

ALTER TABLE projects
    ADD COLUMN ai_mode text NOT NULL DEFAULT 'disabled'
        CHECK (ai_mode IN ('disabled', 'local', 'external'));

ALTER TABLE snapshots
    ADD COLUMN enrichment text CHECK (enrichment IN ('complete', 'incomplete', 'carried')),
    ADD COLUMN enrichment_model text NOT NULL DEFAULT '' CHECK (length(enrichment_model) <= 128);
