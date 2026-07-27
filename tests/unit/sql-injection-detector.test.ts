/**
 * Unit tests for SqlInjectionDetector core detection logic
 * Tests the getTechniqueOrder method for different input types
 */

import { Page } from 'playwright';
import {
  SqlInjectionDetector,
  SqlInjectionTechnique,
} from '../../src/detectors/active/SqlInjectionDetector';
import {
  AttackSurface,
  AttackSurfaceType,
  InjectionContext,
} from '../../src/scanners/active/DomExplorer';

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
      inputType: string = 'text',
      metadata: Record<string, unknown> = {}
    ): AttackSurface => ({
      id: `test-${name}`,
      type,
      name,
      value: '',
      context: InjectionContext.SQL,
      metadata: { inputType, ...metadata },
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

    it('should prioritize auth-bypass for a username with a password companion', () => {
      const surface = createSurface('username', AttackSurfaceType.FORM_INPUT, 'text', {
        otherFields: { '[name="password"]': '' },
      });
      const order = (detector as any).getTechniqueOrder(surface);

      expect(order[0]).toBe('auth-bypass');
    });

    it('should prioritize auth-bypass for an email field on a login route', () => {
      const surface = createSurface('user_email', AttackSurfaceType.FORM_INPUT, 'email', {
        url: 'http://example.test/#/login',
      });
      const order = (detector as any).getTechniqueOrder(surface);

      expect(order[0]).toBe('auth-bypass');
    });

    it('should not treat an ordinary email input as a login field', () => {
      const surface = createSurface('newsletter_email', AttackSurfaceType.FORM_INPUT, 'email');
      const order = (detector as any).getTechniqueOrder(surface);

      expect(order).not.toContain('auth-bypass');
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

  describe('getSqlTargets', () => {
    it('keeps captured API parameters for first-party SQL injection testing', () => {
      const apiParam: AttackSurface = {
        id: 'api-q',
        type: AttackSurfaceType.API_PARAM,
        name: 'q',
        value: 'apple',
        context: InjectionContext.SQL,
        metadata: { url: 'http://127.0.0.1/rest/products/search?q=apple', method: 'GET' },
      };
      const apiEndpoint: AttackSurface = {
        id: 'api-endpoint',
        type: AttackSurfaceType.API_ENDPOINT,
        name: 'products',
        value: '',
        context: InjectionContext.SQL,
        metadata: { url: 'http://127.0.0.1/rest/products/search' },
      };

      const targets = (detector as any).getSqlTargets([apiParam, apiEndpoint]) as AttackSurface[];

      expect(targets).toEqual([apiParam]);
    });
  });

  describe('login boolean payloads', () => {
    it('pairs comment-terminated true and false predicates for authentication forms', () => {
      const surface: AttackSurface = {
        id: 'login-email',
        type: AttackSurfaceType.FORM_INPUT,
        name: 'email',
        value: '',
        context: InjectionContext.SQL,
        metadata: { inputType: 'email' },
      };

      const payloads = (detector as any).getBooleanPayloads(surface);

      expect(payloads.truePayloads[0]).toBe("' OR 1=1--");
      expect(payloads.falsePayloads[0]).toBe("' AND 1=2--");
    });

    it('uses one deadline across the login true/false probes', async () => {
      const detectorWithDeadline = new SqlInjectionDetector({
        techniqueTimeouts: { booleanBased: 1_000 },
      });
      const surface: AttackSurface = {
        id: 'login-email',
        type: AttackSurfaceType.FORM_INPUT,
        name: 'email',
        value: '',
        context: InjectionContext.SQL,
        metadata: { inputType: 'email', url: 'http://juice.test/#/login' },
      };
      const submitProbe = jest
        .spyOn(detectorWithDeadline as any, 'submitAuthenticationProbe')
        .mockResolvedValue({});
      const now = jest
        .spyOn(Date, 'now')
        .mockReturnValueOnce(0)
        .mockReturnValueOnce(0)
        .mockReturnValueOnce(1_000);

      await (detectorWithDeadline as any).testLoginBooleanBased(
        {} as Page,
        surface,
        'http://juice.test'
      );

      expect(submitProbe).toHaveBeenCalledTimes(1);
      expect(submitProbe).toHaveBeenCalledWith(
        expect.anything(),
        surface,
        "' OR 1=1--",
        'http://juice.test/#/login',
        1_000
      );
      now.mockRestore();
    });
  });

  describe('authentication bypass response handling', () => {
    it('waits for the delayed login response before reporting an authentication bypass', async () => {
      const surface: AttackSurface = {
        id: 'login-email',
        type: AttackSurfaceType.FORM_INPUT,
        name: 'email',
        value: '',
        context: InjectionContext.SQL,
        metadata: {
          inputType: 'email',
          url: 'http://juice.test/#/login',
        },
      };
      const loginResponse = {
        headers: () => ({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue({
          authentication: { token: 'kinetic-test-token' },
          user: { email: 'admin@juice.sh' },
        }),
        request: () => ({ method: () => 'POST' }),
        status: () => 200,
        text: jest.fn(),
        url: () => 'http://juice.test/rest/user/login',
      };
      let resolveLoginResponse!: (response: typeof loginResponse) => void;
      const delayedLoginResponse = new Promise<typeof loginResponse>((resolve) => {
        resolveLoginResponse = resolve;
      });
      const page = {
        $: jest.fn().mockResolvedValue(null),
        context: () => ({
          clearCookies: jest.fn().mockResolvedValue(undefined),
          cookies: jest.fn().mockResolvedValue([]),
        }),
        evaluate: jest.fn().mockResolvedValue(false),
        goto: jest.fn().mockResolvedValue(undefined),
        locator: () => ({ count: jest.fn().mockResolvedValue(0) }),
        url: () => 'http://juice.test/#/login',
        waitForResponse: jest.fn((predicate: (candidate: typeof loginResponse) => boolean) => {
          expect(predicate(loginResponse)).toBe(true);
          return delayedLoginResponse;
        }),
      };
      const injector = {
        inject: jest.fn().mockResolvedValue({
          payload: "' OR 1=1--",
          response: {
            body: '',
            headers: {},
            status: 200,
            url: 'http://juice.test/#/login',
          },
        }),
      };
      (detector as any).injector = injector;

      let settled = false;
      const findingPromise = (detector as any)
        .testAuthBypass(page, surface, 'http://juice.test/#/login')
        .then((finding: unknown) => {
          settled = true;
          return finding;
        });

      await new Promise<void>((resolve) => setImmediate(resolve));
      expect(page.waitForResponse).toHaveBeenCalledTimes(1);
      expect(settled).toBe(false);

      resolveLoginResponse(loginResponse);

      const finding = await findingPromise;
      expect(finding).toEqual(
        expect.objectContaining({
          cwe: 'CWE-89',
          title: 'SQL Injection (Authentication Bypass)',
        })
      );
      expect((finding.evidence.metadata as Record<string, unknown>)?.['technique']).toBe(
        'auth-bypass'
      );
      expect(injector.inject).toHaveBeenCalledTimes(1);
    });

    it('does not accept an authentication field set to false as a successful login', () => {
      expect(
        (detector as any).isSuccessfulAuthenticationResponse({
          body: { authentication: false },
          headers: {},
          status: 200,
          url: 'http://juice.test/rest/user/login',
        })
      ).toBe(false);
    });
  });
});
