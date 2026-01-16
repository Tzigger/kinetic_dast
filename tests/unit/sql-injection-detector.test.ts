/**
 * Unit tests for SqlInjectionDetector core detection logic
 * Tests the getTechniqueOrder method for different input types
 */

import { SqlInjectionDetector, SqlInjectionTechnique } from '../../src/detectors/active/SqlInjectionDetector';
import { AttackSurface, AttackSurfaceType, InjectionContext } from '../../src/scanners/active/DomExplorer';

describe('SqlInjectionDetector', () => {
  let detector: SqlInjectionDetector;

  beforeEach(() => {
    detector = new SqlInjectionDetector({
      enableAuthBypass: true,
      enableErrorBased: true,
      enableBooleanBased: true,
      enableTimeBased: true,
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
      context: InjectionContext.SQL,
      metadata: { inputType },
    });

    it('should limit techniques for hidden inputs', () => {
      const surface = createSurface('hidden_field', AttackSurfaceType.FORM_INPUT, 'hidden');
      const order = (detector as any).getTechniqueOrder(surface);
      
      expect(order).toContain(SqlInjectionTechnique.ERROR_BASED);
      expect(order).toContain(SqlInjectionTechnique.BOOLEAN_BASED);
      expect(order).not.toContain(SqlInjectionTechnique.TIME_BASED);
    });

    it('should limit techniques for checkbox inputs', () => {
      const surface = createSurface('checkbox_field', AttackSurfaceType.FORM_INPUT, 'checkbox');
      const order = (detector as any).getTechniqueOrder(surface);
      
      expect(order).toEqual([SqlInjectionTechnique.ERROR_BASED]);
    });

    it('should limit techniques for radio inputs', () => {
      const surface = createSurface('radio_field', AttackSurfaceType.FORM_INPUT, 'radio');
      const order = (detector as any).getTechniqueOrder(surface);
      
      expect(order).toEqual([SqlInjectionTechnique.ERROR_BASED]);
    });

    it('should limit techniques for number inputs', () => {
      const surface = createSurface('quantity', AttackSurfaceType.FORM_INPUT, 'number');
      const order = (detector as any).getTechniqueOrder(surface);
      
      expect(order).toContain(SqlInjectionTechnique.ERROR_BASED);
      expect(order).toContain(SqlInjectionTechnique.BOOLEAN_BASED);
      expect(order).not.toContain(SqlInjectionTechnique.TIME_BASED);
    });

    it('should limit techniques for date inputs', () => {
      const surface = createSurface('birthdate', AttackSurfaceType.FORM_INPUT, 'date');
      const order = (detector as any).getTechniqueOrder(surface);
      
      expect(order).toEqual([SqlInjectionTechnique.ERROR_BASED]);
    });

    it('should prioritize auth-bypass for username fields', () => {
      const surface = createSurface('username', AttackSurfaceType.FORM_INPUT, 'text');
      const order = (detector as any).getTechniqueOrder(surface);
      
      expect(order[0]).toBe('auth-bypass');
    });

    it('should prioritize auth-bypass for email fields', () => {
      const surface = createSurface('user_email', AttackSurfaceType.FORM_INPUT, 'email');
      const order = (detector as any).getTechniqueOrder(surface);
      
      expect(order[0]).toBe('auth-bypass');
    });

    it('should include union-based for search fields', () => {
      const surface = createSurface('search_query', AttackSurfaceType.FORM_INPUT, 'text');
      const order = (detector as any).getTechniqueOrder(surface);
      
      expect(order).toContain(SqlInjectionTechnique.UNION_BASED);
    });

    it('should prioritize boolean-based for JSON body', () => {
      const surface = createSurface('userId', AttackSurfaceType.JSON_BODY, 'text');
      const order = (detector as any).getTechniqueOrder(surface);
      
      expect(order[0]).toBe(SqlInjectionTechnique.BOOLEAN_BASED);
    });

    it('should prioritize error-based for API params', () => {
      const surface = createSurface('id', AttackSurfaceType.API_PARAM, 'text');
      const order = (detector as any).getTechniqueOrder(surface);
      
      expect(order[0]).toBe(SqlInjectionTechnique.ERROR_BASED);
    });

    it('should skip auth-bypass for password fields', () => {
      const surface = createSurface('password', AttackSurfaceType.FORM_INPUT, 'password');
      const order = (detector as any).getTechniqueOrder(surface);
      
      // Password fields should not have auth-bypass as first technique
      expect(order).not.toContain('auth-bypass');
    });

    it('should use default order for regular text inputs', () => {
      const surface = createSurface('comment', AttackSurfaceType.FORM_INPUT, 'text');
      const order = (detector as any).getTechniqueOrder(surface);
      
      expect(order[0]).toBe(SqlInjectionTechnique.ERROR_BASED);
      expect(order[1]).toBe(SqlInjectionTechnique.BOOLEAN_BASED);
      expect(order[2]).toBe(SqlInjectionTechnique.TIME_BASED);
    });
  });

  describe('prioritizeTargets', () => {
    it('should prioritize login-related surfaces', () => {
      const surfaces: AttackSurface[] = [
        {
          id: 'test-1',
          type: AttackSurfaceType.FORM_INPUT,
          name: 'comment_field',
          value: '',
          context: InjectionContext.SQL,
          metadata: { inputType: 'text' },
        },
        {
          id: 'test-2',
          type: AttackSurfaceType.FORM_INPUT,
          name: 'user_login',
          value: '',
          context: InjectionContext.SQL,
          metadata: { inputType: 'text' },
        },
      ];

      const prioritized = (detector as any).prioritizeTargets(surfaces);
      
      // Login-related field should come first
      expect(prioritized[0].name).toBe('user_login');
    });

    it('should prioritize search fields', () => {
      const surfaces: AttackSurface[] = [
        {
          id: 'test-1',
          type: AttackSurfaceType.FORM_INPUT,
          name: 'bio',
          value: '',
          context: InjectionContext.SQL,
          metadata: { inputType: 'text' },
        },
        {
          id: 'test-2',
          type: AttackSurfaceType.FORM_INPUT,
          name: 'search_products',
          value: '',
          context: InjectionContext.SQL,
          metadata: { inputType: 'text' },
        },
      ];

      const prioritized = (detector as any).prioritizeTargets(surfaces);
      
      // Search field should come first
      expect(prioritized[0].name).toBe('search_products');
    });
  });
});
