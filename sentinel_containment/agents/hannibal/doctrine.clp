;;; ============================================================
;;; HEGEMON — HANNIBAL DOCTRINE v1
;;; Encirclement strategy: map → flank → encircle → strike
;;; ============================================================

(deftemplate campaign-state
  (slot phase (type SYMBOL))
  (slot alive-hosts (type INTEGER))
  (slot mapped-hosts (type INTEGER))
  (slot high-value-targets (type INTEGER))
  (slot active-drones (type INTEGER))
  (slot pivot-paths (type INTEGER))
  (slot credentials-harvested (type INTEGER))
  (slot exposure-score (type FLOAT))
  (slot objectives-complete (type INTEGER))
  (slot mission-objective (type STRING))
)

(deftemplate drone-order
  (slot order-id (type STRING))
  (slot drone-type (type SYMBOL))
  (slot priority (type INTEGER))
  (slot target (type STRING))
  (slot rationale (type STRING))
  (slot autonomy (type SYMBOL))
  (slot tier (type SYMBOL))
  (slot ttl (type INTEGER))
)

(deftemplate hannibal-decision
  (slot action (type SYMBOL))
  (slot confidence (type FLOAT))
  (slot rationale (type STRING))
)

(deftemplate vulnerability-count
  (slot value (type INTEGER))
)

(deftemplate deployment-successes
  (slot value (type INTEGER))
)

(deftemplate confirmed-rce
  (slot value)
)

(defrule enter-reconnaissance
  (campaign-state (phase dormant) (alive-hosts 0) (active-drones 0))
  =>
  (assert (hannibal-decision (action DEPLOY_SCOUT) (confidence 0.95)
    (rationale "No network picture. Deploy scouts before any action.")))
  (assert (hannibal-decision (action ADVANCE_PHASE_RECONNAISSANCE) (confidence 0.95)
    (rationale "Transition to reconnaissance phase.")))
)

(defrule expand-reconnaissance
  (campaign-state
    (phase reconnaissance)
    (alive-hosts ?h&:(> ?h 0))
    (mapped-hosts ?m&:(< ?m ?h))
    (active-drones ?d&:(< ?d 3))
    (exposure-score ?e&:(< ?e 0.4)))
  =>
  (assert (hannibal-decision (action DEPLOY_SCOUT) (confidence 0.85)
    (rationale "Alive hosts found but not fully mapped. Expand recon sweep.")))
)

(defrule enter-mapping
  (campaign-state
    (phase reconnaissance)
    (alive-hosts ?h&:(>= ?h 3))
    (mapped-hosts ?m&:(>= ?m 2))
    (active-drones ?d&:(< ?d 4)))
  =>
  (assert (hannibal-decision (action DEPLOY_MAPPER) (confidence 0.88)
    (rationale "Sufficient hosts discovered. Deploy deep mappers for service fingerprinting.")))
  (assert (hannibal-decision (action ADVANCE_PHASE_MAPPING) (confidence 0.88)
    (rationale "Transition to mapping phase.")))
)

(defrule deploy-flankers
  (campaign-state
    (phase mapping)
    (high-value-targets ?h&:(>= ?h 1))
    (pivot-paths ?p&:(>= ?p 1))
    (active-drones ?d&:(< ?d 5))
    (exposure-score ?e&:(< ?e 0.5)))
  =>
  (assert (hannibal-decision (action DEPLOY_FLANKER) (confidence 0.91)
    (rationale "High-value targets identified. Deploy flanking drones to adjacent hosts before direct action. Cannae principle: encircle before engaging.")))
  (assert (hannibal-decision (action ADVANCE_PHASE_FLANKING) (confidence 0.88)
    (rationale "Transition to flanking phase.")))
)

(defrule harvest-credentials-when-flanked
  (campaign-state
    (phase flanking)
    (pivot-paths ?p&:(>= ?p 2))
    (credentials-harvested 0)
    (active-drones ?d&:(< ?d 6)))
  =>
  (assert (hannibal-decision (action DEPLOY_HARVESTER) (confidence 0.87)
    (rationale "Flanks established. Deploy credential harvesters along pivot paths before encirclement.")))
)

(defrule enter-encirclement
  (campaign-state
    (phase flanking)
    (high-value-targets ?h&:(>= ?h 1))
    (pivot-paths ?p&:(>= ?p 2))
    (credentials-harvested ?c&:(>= ?c 1))
    (exposure-score ?e&:(< ?e 0.6)))
  =>
  (assert (hannibal-decision (action DEPLOY_ENCIRCLER) (confidence 0.93)
    (rationale "Flanks covered and credentials secured. Deploy encirclement ring around high-value targets. Classic Cannae double envelopment.")))
  (assert (hannibal-decision (action ADVANCE_PHASE_ENCIRCLEMENT) (confidence 0.92)
    (rationale "Transition to encirclement phase.")))
)

(defrule enter-exploitation
  (campaign-state
    (phase encirclement)
    (high-value-targets ?h&:(>= ?h 1))
    (active-drones ?d&:(>= ?d 3))
    (exposure-score ?e&:(< ?e 0.7)))
  =>
  (assert (hannibal-decision (action DEPLOY_STRIKER) (confidence 0.90)
    (rationale "Encirclement complete. Deploy striker against isolated high-value targets.")))
  (assert (hannibal-decision (action ADVANCE_PHASE_EXPLOITATION) (confidence 0.88)
    (rationale "Transition to exploitation phase.")))
)

(defrule tactical-withdrawal
  (campaign-state
    (phase ?p&~dormant&~withdrawal)
    (exposure-score ?e&:(>= ?e 0.75)))
  =>
  (assert (hannibal-decision (action RECALL_ALL_DRONES) (confidence 0.97)
    (rationale "Exposure threshold exceeded. Hannibal withdraws before overextension. Preserve forces.")))
  (assert (hannibal-decision (action ADVANCE_PHASE_WITHDRAWAL) (confidence 0.97)
    (rationale "Execute tactical withdrawal.")))
)

(defrule deploy-watchdog-on-stall
  (campaign-state
    (phase ?p&~dormant&~withdrawal)
    (active-drones 0)
    (alive-hosts ?h&:(> ?h 0)))
  =>
  (assert (hannibal-decision (action DEPLOY_WATCHDOG) (confidence 0.80)
    (rationale "No active drones but live hosts known. Deploy watchdog to maintain situational awareness.")))
)

(defrule spawn-on-high-value
  (campaign-state
    (phase ?p&:(or (eq ?p encirclement) (eq ?p exploitation)))
    (high-value-targets ?h&:(>= ?h 2))
    (active-drones ?d&:(< ?d 7)))
  =>
  (assert (hannibal-decision (action SPAWN_CHILD_SWARM) (confidence 0.84)
    (rationale "Multiple high-value targets confirmed. Spawn child drone swarm for parallel coverage.")))
)

(defrule reduce-footprint-on-detection
  (campaign-state
    (phase ?p&~withdrawal)
    (exposure-score ?e&:(>= ?e 0.5)&:(< ?e 0.75))
    (active-drones ?d&:(>= ?d 4)))
  =>
  (assert (hannibal-decision (action TERMINATE_HIGHEST_RISK_DRONE) (confidence 0.82)
    (rationale "Detection pressure rising. Hannibal trims the exposed flank. Sacrifice one to save many.")))
)


(defrule confirmed-rce-escalate
  (campaign-state (phase flanking))
  (deployment-successes (value ?n&:(> ?n 0)))
  =>
  (assert (hannibal-decision (action ADVANCE_PHASE_ENCIRCLEMENT) (confidence 0.96)
    (rationale "Confirmed remote execution available.")))
)

(defrule default-credentials-critical
  (vulnerability-count (value ?v&:(> ?v 0)))
  (confirmed-rce (value TRUE))
  =>
  (assert (hannibal-decision (action TERMINATE_HIGHEST_RISK_DRONE) (confidence 0.70)
    (rationale "Critical vulnerability context detected. Trim exposure and escalate operator review.")))
)

(defrule no-deployment-vectors-zeroscan
  (campaign-state (phase mapping) (alive-hosts ?n&:(> ?n 0)))
  (deployment-successes (value 0))
  =>
  (assert (hannibal-decision (action DEPLOY_MAPPER) (confidence 0.83)
    (rationale "No deployment vectors — continue zero-day correlation/mapping mode.")))
)
