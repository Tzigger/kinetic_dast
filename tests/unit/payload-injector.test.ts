import { Page } from 'playwright';
import { PayloadInjector } from '../../src/scanners/active/PayloadInjector';
import {
  AttackSurface,
  AttackSurfaceType,
  InjectionContext,
} from '../../src/scanners/active/DomExplorer';

describe('PayloadInjector URL parameter injection', () => {
  const injectUrlParameter = async (
    initialUrl: string,
    surface: AttackSurface,
    payload: string
  ): Promise<{ targetUrl: URL; goto: jest.Mock }> => {
    let currentUrl = initialUrl;
    const goto = jest.fn(async (url: string) => {
      currentUrl = url;
      return { status: () => 201 };
    });
    const page = {
      isClosed: jest.fn(() => false),
      url: jest.fn(() => currentUrl),
      goto,
      content: jest.fn().mockResolvedValue('<html></html>'),
    } as unknown as Page;
    const injector = new PayloadInjector();
    const injectorWithWaitStrategy = injector as unknown as {
      spaWaitStrategy: { waitForStability: jest.Mock };
    };

    injectorWithWaitStrategy.spaWaitStrategy.waitForStability = jest.fn().mockResolvedValue({});

    await injector.inject(page, surface, payload);

    const target = goto.mock.calls[0]?.[0];
    expect(typeof target).toBe('string');
    expect(goto.mock.calls[0]?.[1]).toEqual({ waitUntil: 'domcontentloaded' });

    return { targetUrl: new URL(target as string), goto };
  };

  it('injects a hash-route parameter without changing the pre-hash query string', async () => {
    const surface: AttackSurface = {
      id: 'hash-search-query',
      type: AttackSurfaceType.URL_PARAMETER,
      name: 'q',
      value: 'original',
      context: InjectionContext.URL,
      metadata: { source: 'hash' },
    };

    const { targetUrl } = await injectUrlParameter(
      'https://example.test/?campaign=landing#/search?q=original&category=fruit',
      surface,
      '<svg/onload=alert(1)>'
    );

    expect(targetUrl.searchParams.get('campaign')).toBe('landing');
    expect(targetUrl.searchParams.get('q')).toBeNull();
    expect(targetUrl.hash.split('?')[0]).toBe('#/search');

    const hashParams = new URLSearchParams(targetUrl.hash.split('?')[1]);
    expect(hashParams.get('q')).toBe('<svg/onload=alert(1)>');
    expect(hashParams.get('category')).toBe('fruit');
  });

  it('continues to inject ordinary URL parameters before a hash route', async () => {
    const surface: AttackSurface = {
      id: 'query-search-query',
      type: AttackSurfaceType.URL_PARAMETER,
      name: 'q',
      value: 'original',
      context: InjectionContext.URL,
      metadata: { source: 'query' },
    };

    const { targetUrl } = await injectUrlParameter(
      'https://example.test/?q=original#/search?q=fragment-value',
      surface,
      'updated'
    );

    expect(targetUrl.searchParams.get('q')).toBe('updated');
    expect(new URLSearchParams(targetUrl.hash.split('?')[1]).get('q')).toBe('fragment-value');
  });
});
