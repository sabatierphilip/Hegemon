export const metaBehaviourDefaults = {
  selfDestruct: {
    findingsLimitEnabled: false,
    findingsLimit: 5,
    anomalyEnabled: false,
    anomalyThreshold: 80,
    hmacFailuresEnabled: true,
    hmacFailures: 3,
    duplicateSelfEnabled: true,
    killSignalEnabled: true,
    ttlExceededEnabled: true
  },
  selfReferential: {
    tightenCheckinEnabled: true,
    tightenThreshold: 3,
    widenCheckinEnabled: true,
    widenCycles: 5,
    updatePayloadFromDeadropEnabled: false,
    replacementEnabled: false,
    escalateAutonomyEnabled: false,
    healthReportEnabled: true,
    healthEveryN: 5
  },
  instanceManagement: {
    maxInstances: '1',
    duplicateAction: 'self-terminate',
    familyTag: '',
    priority: 5
  }
};
