import { AttackSurfaceType, runActiveSecurityScan } from '@tzigger/kinetic';
import { SqlInjectionDetector } from '@tzigger/kinetic/detectors/active/SqlInjectionDetector';
import { runPassiveSecurityScan } from '@tzigger/kinetic/testing';
import { ElementScanner } from '@tzigger/kinetic/scanners/active/ElementScanner';

void [
  AttackSurfaceType,
  runActiveSecurityScan,
  runPassiveSecurityScan,
  SqlInjectionDetector,
  ElementScanner,
];
