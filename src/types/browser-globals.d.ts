/**
 * Type declarations for browser globals used in page.evaluate() contexts
 * These are SPA framework-specific globals that may exist on the window object
 */

declare global {
  interface Window {
    // Angular (2+)
    ng?: unknown;
    getAllAngularTestabilities?: () => Array<{ isStable: () => boolean }>;

    // AngularJS (1.x)
    angular?: {
      version?: { full: string };
      element: (el: Element) => {
        injector: () => {
          get: (name: string) => { pendingRequests: unknown[] };
        } | null;
      };
    };

    // React
    React?: { version?: string };
    __REACT_DEVTOOLS_GLOBAL_HOOK__?: unknown;

    // Vue
    Vue?: { version?: string; nextTick?: (cb: () => void) => void };
    __VUE__?: unknown;
    __VUE_DEVTOOLS_GLOBAL_HOOK__?: {
      apps?: Map<unknown, { _instance?: { isMounted?: boolean } }>;
    };

    // Svelte
    __svelte?: unknown;

    // Ember
    Ember?: { VERSION?: string };

    // Next.js
    __NEXT_DATA__?: unknown;
    __NEXT_HYDRATED?: boolean;
    __NEXT_ROUTER__?: { isReady?: boolean };

    // Nuxt.js
    __NUXT__?: { err: unknown };
    $nuxt?: { $nextTick?: (cb: () => void) => void };
  }

  interface Element {
    _reactRootContainer?: {
      _internalRoot?: { current?: unknown };
    };
  }
}

export {};
