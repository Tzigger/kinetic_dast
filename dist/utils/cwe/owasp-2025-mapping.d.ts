export declare enum OWASP2025Category {
    A01_BROKEN_ACCESS_CONTROL = "A01:2025",
    A02_SECURITY_MISCONFIGURATION = "A02:2025",
    A03_SOFTWARE_SUPPLY_CHAIN = "A03:2025",
    A04_CRYPTOGRAPHIC_FAILURES = "A04:2025",
    A05_INJECTION = "A05:2025",
    A06_INSECURE_DESIGN = "A06:2025",
    A07_AUTHENTICATION_FAILURES = "A07:2025",
    A08_SOFTWARE_DATA_INTEGRITY = "A08:2025",
    A09_LOGGING_ALERTING_FAILURES = "A09:2025",
    A10_MISHANDLING_EXCEPTIONAL_CONDITIONS = "A10:2025"
}
export declare const A01_BROKEN_ACCESS_CONTROL_CWES: string[];
export declare const A02_SECURITY_MISCONFIGURATION_CWES: string[];
export declare const A03_SOFTWARE_SUPPLY_CHAIN_CWES: string[];
export declare const A04_CRYPTOGRAPHIC_FAILURES_CWES: string[];
export declare const A05_INJECTION_CWES: string[];
export declare const A06_INSECURE_DESIGN_CWES: string[];
export declare const A07_AUTHENTICATION_FAILURES_CWES: string[];
export declare const A08_SOFTWARE_DATA_INTEGRITY_CWES: string[];
export declare const A09_LOGGING_ALERTING_FAILURES_CWES: string[];
export declare const A10_MISHANDLING_EXCEPTIONAL_CONDITIONS_CWES: string[];
export declare function getOWASP2025Category(cwe: string): OWASP2025Category | null;
export declare function getCWEsForOWASPCategory(category: OWASP2025Category): string[];
export declare const OWASP2025Stats: {
    "A01:2025": {
        rank: number;
        prevalence: string;
        cweCount: number;
        description: string;
    };
    "A02:2025": {
        rank: number;
        prevalence: string;
        cweCount: number;
        description: string;
    };
    "A03:2025": {
        rank: number;
        prevalence: string;
        cweCount: number;
        description: string;
        highestExploit: boolean;
    };
    "A04:2025": {
        rank: number;
        prevalence: string;
        cweCount: number;
        description: string;
    };
    "A05:2025": {
        rank: number;
        prevalence: string;
        cweCount: number;
        description: string;
        mostTested: boolean;
    };
    "A06:2025": {
        rank: number;
        prevalence: string;
        cweCount: number;
        description: string;
    };
    "A07:2025": {
        rank: number;
        prevalence: string;
        cweCount: number;
        description: string;
    };
    "A08:2025": {
        rank: number;
        prevalence: string;
        cweCount: number;
        description: string;
    };
    "A09:2025": {
        rank: number;
        prevalence: string;
        cweCount: number;
        description: string;
    };
    "A10:2025": {
        rank: number;
        prevalence: string;
        cweCount: number;
        description: string;
        newIn2025: boolean;
    };
};
//# sourceMappingURL=owasp-2025-mapping.d.ts.map