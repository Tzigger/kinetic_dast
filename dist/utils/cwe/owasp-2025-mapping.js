export var OWASP2025Category;
(function (OWASP2025Category) {
    OWASP2025Category["A01_BROKEN_ACCESS_CONTROL"] = "A01:2025";
    OWASP2025Category["A02_SECURITY_MISCONFIGURATION"] = "A02:2025";
    OWASP2025Category["A03_SOFTWARE_SUPPLY_CHAIN"] = "A03:2025";
    OWASP2025Category["A04_CRYPTOGRAPHIC_FAILURES"] = "A04:2025";
    OWASP2025Category["A05_INJECTION"] = "A05:2025";
    OWASP2025Category["A06_INSECURE_DESIGN"] = "A06:2025";
    OWASP2025Category["A07_AUTHENTICATION_FAILURES"] = "A07:2025";
    OWASP2025Category["A08_SOFTWARE_DATA_INTEGRITY"] = "A08:2025";
    OWASP2025Category["A09_LOGGING_ALERTING_FAILURES"] = "A09:2025";
    OWASP2025Category["A10_MISHANDLING_EXCEPTIONAL_CONDITIONS"] = "A10:2025";
})(OWASP2025Category || (OWASP2025Category = {}));
export const A01_BROKEN_ACCESS_CONTROL_CWES = [
    'CWE-22',
    'CWE-23',
    'CWE-35',
    'CWE-59',
    'CWE-200',
    'CWE-201',
    'CWE-219',
    'CWE-264',
    'CWE-275',
    'CWE-276',
    'CWE-284',
    'CWE-285',
    'CWE-352',
    'CWE-359',
    'CWE-377',
    'CWE-402',
    'CWE-425',
    'CWE-441',
    'CWE-497',
    'CWE-538',
    'CWE-540',
    'CWE-548',
    'CWE-552',
    'CWE-566',
    'CWE-601',
    'CWE-639',
    'CWE-651',
    'CWE-668',
    'CWE-706',
    'CWE-862',
    'CWE-863',
    'CWE-913',
    'CWE-918',
    'CWE-922',
    'CWE-1275',
    'CWE-552',
    'CWE-434',
    'CWE-829',
    'CWE-98',
    'CWE-99',
];
export const A02_SECURITY_MISCONFIGURATION_CWES = [
    'CWE-2',
    'CWE-11',
    'CWE-13',
    'CWE-15',
    'CWE-16',
    'CWE-260',
    'CWE-315',
    'CWE-520',
    'CWE-526',
    'CWE-537',
    'CWE-541',
    'CWE-547',
    'CWE-611',
    'CWE-614',
    'CWE-756',
    'CWE-942',
];
export const A03_SOFTWARE_SUPPLY_CHAIN_CWES = [
    'CWE-829',
    'CWE-830',
    'CWE-915',
    'CWE-1104',
    'CWE-1329',
];
export const A04_CRYPTOGRAPHIC_FAILURES_CWES = [
    'CWE-261',
    'CWE-296',
    'CWE-310',
    'CWE-319',
    'CWE-321',
    'CWE-322',
    'CWE-323',
    'CWE-324',
    'CWE-325',
    'CWE-326',
    'CWE-327',
    'CWE-328',
    'CWE-329',
    'CWE-330',
    'CWE-331',
    'CWE-335',
    'CWE-336',
    'CWE-337',
    'CWE-338',
    'CWE-340',
    'CWE-347',
    'CWE-523',
    'CWE-757',
    'CWE-759',
    'CWE-760',
    'CWE-780',
    'CWE-818',
    'CWE-916',
    'CWE-261',
    'CWE-312',
    'CWE-311',
    'CWE-326',
];
export const A05_INJECTION_CWES = [
    'CWE-20',
    'CWE-74',
    'CWE-75',
    'CWE-77',
    'CWE-78',
    'CWE-79',
    'CWE-80',
    'CWE-83',
    'CWE-87',
    'CWE-88',
    'CWE-89',
    'CWE-90',
    'CWE-91',
    'CWE-93',
    'CWE-94',
    'CWE-95',
    'CWE-96',
    'CWE-97',
    'CWE-98',
    'CWE-99',
    'CWE-100',
    'CWE-113',
    'CWE-116',
    'CWE-138',
    'CWE-184',
    'CWE-470',
    'CWE-471',
    'CWE-564',
    'CWE-610',
    'CWE-643',
    'CWE-644',
    'CWE-652',
    'CWE-917',
    'CWE-1236',
    'CWE-694',
    'CWE-917',
    'CWE-943',
    'CWE-1333',
];
export const A06_INSECURE_DESIGN_CWES = [
    'CWE-73',
    'CWE-183',
    'CWE-209',
    'CWE-213',
    'CWE-235',
    'CWE-256',
    'CWE-257',
    'CWE-266',
    'CWE-269',
    'CWE-280',
    'CWE-311',
    'CWE-312',
    'CWE-313',
    'CWE-316',
    'CWE-419',
    'CWE-430',
    'CWE-434',
    'CWE-444',
    'CWE-451',
    'CWE-472',
    'CWE-501',
    'CWE-522',
    'CWE-525',
    'CWE-539',
    'CWE-579',
    'CWE-598',
    'CWE-602',
    'CWE-642',
    'CWE-646',
    'CWE-650',
    'CWE-653',
    'CWE-656',
    'CWE-657',
    'CWE-799',
    'CWE-807',
    'CWE-840',
    'CWE-841',
    'CWE-927',
    'CWE-1021',
    'CWE-1173',
];
export const A07_AUTHENTICATION_FAILURES_CWES = [
    'CWE-255',
    'CWE-259',
    'CWE-287',
    'CWE-288',
    'CWE-290',
    'CWE-294',
    'CWE-295',
    'CWE-297',
    'CWE-300',
    'CWE-302',
    'CWE-304',
    'CWE-306',
    'CWE-307',
    'CWE-346',
    'CWE-384',
    'CWE-521',
    'CWE-522',
    'CWE-598',
    'CWE-603',
    'CWE-613',
    'CWE-620',
    'CWE-640',
    'CWE-798',
    'CWE-1216',
    'CWE-308',
    'CWE-319',
    'CWE-523',
    'CWE-549',
    'CWE-565',
    'CWE-568',
    'CWE-640',
    'CWE-645',
    'CWE-759',
    'CWE-760',
    'CWE-916',
    'CWE-1390',
];
export const A08_SOFTWARE_DATA_INTEGRITY_CWES = [
    'CWE-345',
    'CWE-353',
    'CWE-426',
    'CWE-494',
    'CWE-502',
    'CWE-565',
    'CWE-784',
    'CWE-829',
    'CWE-830',
    'CWE-915',
];
export const A09_LOGGING_ALERTING_FAILURES_CWES = [
    'CWE-117',
    'CWE-223',
    'CWE-532',
    'CWE-778',
    'CWE-117',
    'CWE-223',
    'CWE-532',
    'CWE-778',
];
export const A10_MISHANDLING_EXCEPTIONAL_CONDITIONS_CWES = [
    'CWE-248',
    'CWE-252',
    'CWE-253',
    'CWE-390',
    'CWE-391',
    'CWE-392',
    'CWE-396',
    'CWE-397',
    'CWE-404',
    'CWE-431',
    'CWE-476',
    'CWE-600',
    'CWE-703',
    'CWE-705',
    'CWE-754',
    'CWE-755',
    'CWE-756',
    'CWE-757',
    'CWE-230',
    'CWE-231',
    'CWE-232',
    'CWE-233',
    'CWE-393',
    'CWE-544',
];
export function getOWASP2025Category(cwe) {
    const cweNum = cwe.replace('CWE-', '');
    if (A01_BROKEN_ACCESS_CONTROL_CWES.includes(`CWE-${cweNum}`)) {
        return OWASP2025Category.A01_BROKEN_ACCESS_CONTROL;
    }
    if (A02_SECURITY_MISCONFIGURATION_CWES.includes(`CWE-${cweNum}`)) {
        return OWASP2025Category.A02_SECURITY_MISCONFIGURATION;
    }
    if (A03_SOFTWARE_SUPPLY_CHAIN_CWES.includes(`CWE-${cweNum}`)) {
        return OWASP2025Category.A03_SOFTWARE_SUPPLY_CHAIN;
    }
    if (A04_CRYPTOGRAPHIC_FAILURES_CWES.includes(`CWE-${cweNum}`)) {
        return OWASP2025Category.A04_CRYPTOGRAPHIC_FAILURES;
    }
    if (A05_INJECTION_CWES.includes(`CWE-${cweNum}`)) {
        return OWASP2025Category.A05_INJECTION;
    }
    if (A06_INSECURE_DESIGN_CWES.includes(`CWE-${cweNum}`)) {
        return OWASP2025Category.A06_INSECURE_DESIGN;
    }
    if (A07_AUTHENTICATION_FAILURES_CWES.includes(`CWE-${cweNum}`)) {
        return OWASP2025Category.A07_AUTHENTICATION_FAILURES;
    }
    if (A08_SOFTWARE_DATA_INTEGRITY_CWES.includes(`CWE-${cweNum}`)) {
        return OWASP2025Category.A08_SOFTWARE_DATA_INTEGRITY;
    }
    if (A09_LOGGING_ALERTING_FAILURES_CWES.includes(`CWE-${cweNum}`)) {
        return OWASP2025Category.A09_LOGGING_ALERTING_FAILURES;
    }
    if (A10_MISHANDLING_EXCEPTIONAL_CONDITIONS_CWES.includes(`CWE-${cweNum}`)) {
        return OWASP2025Category.A10_MISHANDLING_EXCEPTIONAL_CONDITIONS;
    }
    return null;
}
export function getCWEsForOWASPCategory(category) {
    switch (category) {
        case OWASP2025Category.A01_BROKEN_ACCESS_CONTROL:
            return A01_BROKEN_ACCESS_CONTROL_CWES;
        case OWASP2025Category.A02_SECURITY_MISCONFIGURATION:
            return A02_SECURITY_MISCONFIGURATION_CWES;
        case OWASP2025Category.A03_SOFTWARE_SUPPLY_CHAIN:
            return A03_SOFTWARE_SUPPLY_CHAIN_CWES;
        case OWASP2025Category.A04_CRYPTOGRAPHIC_FAILURES:
            return A04_CRYPTOGRAPHIC_FAILURES_CWES;
        case OWASP2025Category.A05_INJECTION:
            return A05_INJECTION_CWES;
        case OWASP2025Category.A06_INSECURE_DESIGN:
            return A06_INSECURE_DESIGN_CWES;
        case OWASP2025Category.A07_AUTHENTICATION_FAILURES:
            return A07_AUTHENTICATION_FAILURES_CWES;
        case OWASP2025Category.A08_SOFTWARE_DATA_INTEGRITY:
            return A08_SOFTWARE_DATA_INTEGRITY_CWES;
        case OWASP2025Category.A09_LOGGING_ALERTING_FAILURES:
            return A09_LOGGING_ALERTING_FAILURES_CWES;
        case OWASP2025Category.A10_MISHANDLING_EXCEPTIONAL_CONDITIONS:
            return A10_MISHANDLING_EXCEPTIONAL_CONDITIONS_CWES;
        default:
            return [];
    }
}
export const OWASP2025Stats = {
    [OWASP2025Category.A01_BROKEN_ACCESS_CONTROL]: {
        rank: 1,
        prevalence: '3.73%',
        cweCount: 40,
        description: 'Violations of access control policy, including SSRF',
    },
    [OWASP2025Category.A02_SECURITY_MISCONFIGURATION]: {
        rank: 2,
        prevalence: '3.00%',
        cweCount: 16,
        description: 'Insecure default configs, incomplete configs, misconfigured headers',
    },
    [OWASP2025Category.A03_SOFTWARE_SUPPLY_CHAIN]: {
        rank: 3,
        prevalence: 'Limited',
        cweCount: 5,
        description: 'Compromises in dependencies, build systems, distribution',
        highestExploit: true,
    },
    [OWASP2025Category.A04_CRYPTOGRAPHIC_FAILURES]: {
        rank: 4,
        prevalence: '3.80%',
        cweCount: 32,
        description: 'Failures related to cryptography leading to data exposure',
    },
    [OWASP2025Category.A05_INJECTION]: {
        rank: 5,
        prevalence: 'High',
        cweCount: 38,
        description: 'XSS, SQL injection, command injection, etc.',
        mostTested: true,
    },
    [OWASP2025Category.A06_INSECURE_DESIGN]: {
        rank: 6,
        prevalence: 'Medium',
        cweCount: 40,
        description: 'Missing or ineffective control design',
    },
    [OWASP2025Category.A07_AUTHENTICATION_FAILURES]: {
        rank: 7,
        prevalence: 'Medium',
        cweCount: 36,
        description: 'Broken authentication and session management',
    },
    [OWASP2025Category.A08_SOFTWARE_DATA_INTEGRITY]: {
        rank: 8,
        prevalence: 'Low',
        cweCount: 10,
        description: 'Code/data integrity failures, insecure deserialization',
    },
    [OWASP2025Category.A09_LOGGING_ALERTING_FAILURES]: {
        rank: 9,
        prevalence: 'Low',
        cweCount: 4,
        description: 'Insufficient logging, monitoring, and alerting',
    },
    [OWASP2025Category.A10_MISHANDLING_EXCEPTIONAL_CONDITIONS]: {
        rank: 10,
        prevalence: 'Medium',
        cweCount: 24,
        description: 'Improper error handling, failing open, logical errors',
        newIn2025: true,
    },
};
//# sourceMappingURL=owasp-2025-mapping.js.map