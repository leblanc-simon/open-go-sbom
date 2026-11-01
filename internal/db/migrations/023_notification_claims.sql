-- 023_notification_claims : réservation des envois de notification (recette du lot 2,
-- T18, ADR 0052).
--
-- Deux jobs d'envoi d'un même canal pouvaient tourner en même temps (la clé d'unicité des
-- jobs ne vaut que pour ceux en attente) et envoyer deux fois le même lot. L'envoi réserve
-- désormais ses violations, sous le verrou de la ligne du canal, avant l'appel réseau :
-- claimed_at est l'instant de la réservation, NULL quand l'envoi est libre ; une
-- réservation plus ancienne que dix minutes (au-delà de notify.timeout, 5 min au plus)
-- est celle d'un envoi interrompu et se reprend.
ALTER TABLE notification_deliveries ADD COLUMN claimed_at timestamptz,
    ADD CHECK (state = 'pending' OR claimed_at IS NULL);
