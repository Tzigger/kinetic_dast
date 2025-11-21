export class BaseDetector {
    enabledByDefault = true;
    async validate(vulnerability) {
        return (vulnerability.confidence ?? 0.8) > 0.5;
    }
    getCWEReferences() {
        return [];
    }
    getOWASPReferences() {
        return [];
    }
    createVulnerability(params) {
        return {
            id: this.generateId(),
            category: this.category,
            severity: params.severity,
            title: params.title,
            description: params.description,
            evidence: params.evidence,
            remediation: params.remediation,
            references: params.references || [],
            cwe: params.cwe,
            owasp: params.owasp,
            timestamp: new Date(),
            confidence: params.confidence || 0.8,
            confirmed: false,
            detectorId: this.id,
        };
    }
    generateId() {
        return `${this.id}-${Date.now()}-${Math.random().toString(36).substring(7)}`;
    }
    calculateConfidence(factors) {
        if (factors.length === 0)
            return 0;
        const sum = factors.reduce((acc, val) => acc + val, 0);
        return Math.min(sum / factors.length, 1.0);
    }
}
//# sourceMappingURL=IDetector.js.map