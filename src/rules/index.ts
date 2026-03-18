// ─── Rules Registry ────────────────────────────────────────────────────────────

import { SecurityRule } from '../types';

// A01
import { pathTraversal, corsWildcard, idor } from './A01_access_control';
// A02
import { hardcodedSecrets, weakHash, insecureRandom, insecureHttp, ecbMode } from './A02_cryptographic';
// A03
import { sqlInjection, commandInjection, xss, evalInjection, ldapInjection } from './A03_injection';
// A04–A10
import {
  massAssignment, missingRateLimit,
  debugEnabled, defaultCredentials, exposedStackTrace, missingSecurityHeaders,
  jwtNoneAlgorithm, weakPasswordPolicy, sessionFixation,
  insecureDeserialization,
  sensitiveDataInLogs, missingErrorHandling,
  ssrf,
} from './A04_A10_rules';

export const ALL_RULES: SecurityRule[] = [
  // A01
  pathTraversal, corsWildcard, idor,
  // A02
  hardcodedSecrets, weakHash, insecureRandom, insecureHttp, ecbMode,
  // A03
  sqlInjection, commandInjection, xss, evalInjection, ldapInjection,
  // A04
  massAssignment, missingRateLimit,
  // A05
  debugEnabled, defaultCredentials, exposedStackTrace, missingSecurityHeaders,
  // A07
  jwtNoneAlgorithm, weakPasswordPolicy, sessionFixation,
  // A08
  insecureDeserialization,
  // A09
  sensitiveDataInLogs, missingErrorHandling,
  // A10
  ssrf,
];
