/**
 * Unit tests for XssDetector core detection logic
 * Tests the getTechniqueOrder method for different input types
 */

import { XssDetector, XssType } from '../../src/detectors/active/XssDetector';
import { AttackSurface, AttackSurfaceType, InjectionContext } from '../../src/scanners/active/DomExplorer';

describe('XssDetector', () => {
  let detector: XssDetector;

  beforeEach(() => {
    detector = new XssDetector({
      enableReflected: true,
      enableStored: true,
      enableDomBased: true,
      enableAngularTemplate: true,
      enableJsonXss: true,
    });
  });

  describe('getTechniqueOrder', () => {
    // Helper to create test surfaces
    const createSurface = (
      name: string,
      type: AttackSurfaceType,
      inputType: string = 'text'
    ): AttackSurface => ({
      id: `test-${name}`,
      type,
      name,
      value: '',
      context: InjectionContext.HTML,
      metadata: { inputType },
    });

    it('should limit techniques for hidden inputs', () => {
      const surface = createSurface('hidden_token', AttackSurfaceType.FORM_INPUT, 'hidden');
      const order = (detector as any).getTechniqueOrder(surface);
      
      expect(order).toContain(XssType.REFLECTED);
      expect(order).toContain(XssType.JSON_XSS);
      expect(order).not.toContain(XssType.DOM_BASED);
      expect(order).not.toContain(XssType.STORED);
    });

    it('should limit techniques for checkbox inputs', () => {
      const surface = createSurface('accept_terms', AttackSurfaceType.FORM_INPUT, 'checkbox');
      const order = (detector as any).getTechniqueOrder(surface);
      
      expect(order).toEqual([XssType.REFLECTED]);
    });

    it('should limit techniques for radio inputs', () => {
      const surface = createSurface('gender', AttackSurfaceType.FORM_INPUT, 'radio');
      const order = (detector as any).getTechniqueOrder(surface);
      
      expect(order).toEqual([XssType.REFLECTED]);
    });

    it('should limit techniques for number inputs', () => {
      const surface = createSurface('quantity', AttackSurfaceType.FORM_INPUT, 'number');
      const order = (detector as any).getTechniqueOrder(surface);
      
      expect(order).toEqual([XssType.REFLECTED]);
    });

    it('should limit techniques for date inputs', () => {
      const surface = createSurface('start_date', AttackSurfaceType.FORM_INPUT, 'date');
      const order = (detector as any).getTechniqueOrder(surface);
      
      expect(order).toEqual([XssType.REFLECTED]);
    });

    it('should prioritize JSON XSS for API params', () => {
      const surface = createSurface('data', AttackSurfaceType.API_PARAM, 'text');
      const order = (detector as any).getTechniqueOrder(surface);
      
      expect(order[0]).toBe(XssType.JSON_XSS);
    });

    it('should prioritize JSON XSS for JSON body', () => {
      const surface = createSurface('message', AttackSurfaceType.JSON_BODY, 'text');
      const order = (detector as any).getTechniqueOrder(surface);
      
      expect(order[0]).toBe(XssType.JSON_XSS);
    });

    it('should prioritize reflected for URL parameters', () => {
      const surface = createSurface('query', AttackSurfaceType.URL_PARAMETER, 'text');
      const order = (detector as any).getTechniqueOrder(surface);
      
      expect(order[0]).toBe(XssType.REFLECTED);
      expect(order[1]).toBe(XssType.DOM_BASED);
    });

    it('should prioritize reflected for links', () => {
      const surface = createSurface('redirect', AttackSurfaceType.LINK, 'text');
      const order = (detector as any).getTechniqueOrder(surface);
      
      expect(order[0]).toBe(XssType.REFLECTED);
    });

    it('should include all techniques for form text inputs', () => {
      const surface = createSurface('comment', AttackSurfaceType.FORM_INPUT, 'text');
      const order = (detector as any).getTechniqueOrder(surface);
      
      expect(order).toContain(XssType.REFLECTED);
      expect(order).toContain(XssType.DOM_BASED);
      expect(order).toContain(XssType.STORED);
      expect(order).toContain(XssType.ANGULAR_TEMPLATE);
    });

    it('should include stored XSS for textarea', () => {
      const surface = createSurface('bio', AttackSurfaceType.FORM_INPUT, 'textarea');
      const order = (detector as any).getTechniqueOrder(surface);
      
      expect(order).toContain(XssType.STORED);
    });
  });

  describe('shouldSkipTechnique', () => {
    it('should skip expensive techniques when high confidence finding exists', () => {
      const findings = [{
        id: 'vuln-1',
        title: 'XSS',
        cwe: 'CWE-79',
        severity: 'high',
        evidence: {
          metadata: { confidence: 0.9 }
        }
      }];

      const skipDomBased = (detector as any).shouldSkipTechnique(XssType.DOM_BASED, findings);
      const skipReflected = (detector as any).shouldSkipTechnique(XssType.REFLECTED, findings);
      
      expect(skipDomBased).toBe(true);
      expect(skipReflected).toBe(false);
    });

    it('should not skip any techniques when no high confidence findings', () => {
      const findings = [{
        id: 'vuln-1',
        title: 'XSS',
        cwe: 'CWE-79',
        severity: 'low',
        evidence: {
          metadata: { confidence: 0.3 }
        }
      }];

      const skipDomBased = (detector as any).shouldSkipTechnique(XssType.DOM_BASED, findings);
      const skipStored = (detector as any).shouldSkipTechnique(XssType.STORED, findings);
      
      expect(skipDomBased).toBe(false);
      expect(skipStored).toBe(false);
    });
  });
});
