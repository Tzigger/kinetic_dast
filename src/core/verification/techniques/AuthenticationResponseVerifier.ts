import { Page } from 'playwright';

import {
  AttackSurface,
  AttackSurfaceType,
  InjectionContext,
} from '../../../scanners/active/DomExplorer';
import { PayloadEncoding, PayloadInjector } from '../../../scanners/active/PayloadInjector';
import {
  VerificationConfig,
  VerificationResult,
  VerificationStatus,
} from '../../../types/verification';
import { Vulnerability } from '../../../types/vulnerability';

interface AuthenticationProbeMetadata {
  pageUrl: string;
  selector: string;
  passwordSelector?: string;
  endpointPath?: string;
  method: string;
  truePayload: string;
  falsePayload: string;
}

interface AuthenticationResponse {
  body: unknown;
  status: number;
}

/**
 * Replays login SQL injection findings using the exact login form and a
 * positive/negative response pair captured by the detector. Generic response
 * diff verification cannot reconstruct a form locator from a payload alone.
 */
export class AuthenticationResponseVerifier {
  private readonly injector = new PayloadInjector();

  constructor() {
    this.injector.setSafeMode(true);
  }

  public async verify(
    page: Page,
    vulnerability: Vulnerability,
    config: VerificationConfig
  ): Promise<VerificationResult | null> {
    const probe = this.getProbeMetadata(vulnerability);
    if (!probe) {
      return null;
    }

    const deadline = Date.now() + config.attemptTimeout;
    const trueResponse = await this.submitProbe(
      page,
      probe,
      probe.truePayload,
      Math.max(0, deadline - Date.now())
    );
    const falseResponse = await this.submitProbe(
      page,
      probe,
      probe.falsePayload,
      Math.max(0, deadline - Date.now())
    );

    if (!trueResponse || !falseResponse) {
      return this.createResult(
        vulnerability,
        VerificationStatus.INCONCLUSIVE,
        0,
        'Could not capture both authentication responses during replay'
      );
    }

    const trueAuthenticated = this.isAuthenticationSuccess(trueResponse);
    const falseAuthenticated = this.isAuthenticationSuccess(falseResponse);
    const hasDifferential =
      trueResponse.status !== falseResponse.status || falseResponse.status >= 400;

    if (trueAuthenticated && !falseAuthenticated && hasDifferential) {
      return this.createResult(
        vulnerability,
        VerificationStatus.CONFIRMED,
        1,
        `Authentication response replay confirmed (${trueResponse.status} authenticated vs ${falseResponse.status} rejected)`
      );
    }

    return this.createResult(
      vulnerability,
      VerificationStatus.FALSE_POSITIVE,
      0,
      `Authentication response replay did not reproduce the expected differential (${trueResponse.status} vs ${falseResponse.status})`
    );
  }

  private getProbeMetadata(vulnerability: Vulnerability): AuthenticationProbeMetadata | null {
    const candidate = vulnerability.evidence.metadata?.['authenticationProbe'];
    if (!candidate || typeof candidate !== 'object') {
      return null;
    }

    const metadata = candidate as Record<string, unknown>;
    const pageUrl = metadata['pageUrl'];
    const selector = metadata['selector'];
    const truePayload = metadata['truePayload'];
    const falsePayload = metadata['falsePayload'];
    const method = metadata['method'];

    if (
      typeof pageUrl !== 'string' ||
      typeof selector !== 'string' ||
      typeof truePayload !== 'string' ||
      typeof falsePayload !== 'string' ||
      typeof method !== 'string'
    ) {
      return null;
    }

    const passwordSelector = metadata['passwordSelector'];
    const endpointPath = metadata['endpointPath'];
    return {
      pageUrl,
      selector,
      truePayload,
      falsePayload,
      method,
      ...(typeof passwordSelector === 'string' ? { passwordSelector } : {}),
      ...(typeof endpointPath === 'string' ? { endpointPath } : {}),
    };
  }

  private async submitProbe(
    page: Page,
    probe: AuthenticationProbeMetadata,
    payload: string,
    timeout: number
  ): Promise<AuthenticationResponse | null> {
    if (timeout <= 0 || !(await this.resetAuthenticationState(page, probe.pageUrl, timeout))) {
      return null;
    }

    const responsePromise = this.waitForAuthenticationResponse(page, probe, timeout);
    const surface: AttackSurface = {
      id: 'authentication-replay',
      type: AttackSurfaceType.FORM_INPUT,
      name: 'authentication input',
      selector: probe.selector,
      value: '',
      context: InjectionContext.SQL,
      metadata: {
        otherFields: {
          [probe.passwordSelector || 'input[type="password"]']: 'kinetic-auth-probe',
        },
      },
    };

    try {
      await this.injector.inject(page, surface, payload, {
        encoding: PayloadEncoding.NONE,
        submit: true,
        stabilityTimeoutMs: 0,
      });
    } catch {
      // Await the scoped response waiter below: form submission can complete
      // even if the browser-side injection path reports an error.
    }

    return responsePromise;
  }

  private async resetAuthenticationState(
    page: Page,
    pageUrl: string,
    timeout: number
  ): Promise<boolean> {
    try {
      await page
        .evaluate(() => {
          const clearAuthenticationKeys = (storage: Storage): void => {
            for (let index = storage.length - 1; index >= 0; index -= 1) {
              const key = storage.key(index);
              if (key && /auth|token|session|jwt|user/i.test(key)) {
                storage.removeItem(key);
              }
            }
          };

          clearAuthenticationKeys(localStorage);
          clearAuthenticationKeys(sessionStorage);
        })
        .catch(() => undefined);
      // Cookies do not consistently identify which one carries the session,
      // so isolation needs a clean context-wide cookie jar for this replay.
      await page.context().clearCookies();
      await page.goto(pageUrl, {
        waitUntil: 'domcontentloaded',
        timeout: Math.max(1, Math.min(timeout, 10000)),
      });
      await page
        .waitForSelector('body', {
          state: 'attached',
          timeout: Math.max(1, Math.min(timeout, 5000)),
        })
        .catch(() => undefined);
      return true;
    } catch {
      return false;
    }
  }

  private async waitForAuthenticationResponse(
    page: Page,
    probe: AuthenticationProbeMetadata,
    timeout: number
  ): Promise<AuthenticationResponse | null> {
    try {
      const response = await page.waitForResponse(
        (candidate) => {
          if (candidate.request().method().toUpperCase() !== probe.method.toUpperCase()) {
            return false;
          }

          if (!probe.endpointPath) {
            return /\/login(?:[/?#]|$)/i.test(candidate.url());
          }

          try {
            return new URL(candidate.url()).pathname === probe.endpointPath;
          } catch {
            return false;
          }
        },
        { timeout }
      );

      let body: unknown;
      try {
        body = await response.json();
      } catch {
        try {
          body = await response.text();
        } catch {
          body = null;
        }
      }

      return { body, status: response.status() };
    } catch {
      return null;
    }
  }

  private isAuthenticationSuccess(response: AuthenticationResponse): boolean {
    if (response.status < 200 || response.status >= 300) {
      return false;
    }

    const body = typeof response.body === 'string' ? response.body : JSON.stringify(response.body);
    return (
      /"(?:token|jwt)"\s*:\s*"[^"\s][^"]*"/i.test(body) ||
      /"authenticated"\s*:\s*true\b/i.test(body)
    );
  }

  private createResult(
    vulnerability: Vulnerability,
    status: VerificationStatus,
    confidence: number,
    reason: string
  ): VerificationResult {
    return {
      vulnerability,
      status,
      confidence,
      attempts: [],
      totalDuration: 0,
      shouldReport:
        status === VerificationStatus.CONFIRMED || status === VerificationStatus.VERIFIED,
      reason,
    };
  }
}
