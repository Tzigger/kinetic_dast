import { VulnerabilityCategory } from '../../types/enums';
export interface CWEInfo {
    id: string;
    name: string;
    description: string;
    references: string[];
}
export declare const CWE_MAPPING: Record<string, CWEInfo>;
export declare const CATEGORY_TO_CWE: Record<VulnerabilityCategory, string[]>;
export declare function getCWEInfo(cweId: string): CWEInfo | null;
export declare function getCWEsForCategory(category: VulnerabilityCategory): string[];
export declare function getPrimaryCWE(category: VulnerabilityCategory): string | null;
export declare function mapVulnerabilityToCWE(vulnerability: any): any;
export declare function getCWEInfoForCategory(category: VulnerabilityCategory): CWEInfo[];
//# sourceMappingURL=cwe-mapping.d.ts.map