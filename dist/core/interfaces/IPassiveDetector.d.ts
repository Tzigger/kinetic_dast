import { Vulnerability } from '../../types/vulnerability';
export interface IPassiveDetector {
    detect(data: any): Promise<Vulnerability[]>;
    validate(): Promise<boolean>;
    getPatterns(): RegExp[];
}
//# sourceMappingURL=IPassiveDetector.d.ts.map