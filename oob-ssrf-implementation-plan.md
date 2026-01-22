# OOB SSRF Implementation Plan

## Current State Analysis

### Already Implemented
- OOBClient interface and MockOOBClient in src/core/network/OOBClient.ts
- Advanced SSRF detector with three detection strategies:
  - Reflected/Error-Based Detection
  - Timing-Based Blind Detection  
  - OOB-Based Blind Detection
- Advanced payload categories:
  - WAF Bypass (IPv6, Decimal, Hex, Octal, DNS rebinding)
  - Cloud Metadata (AWS, GCP, Azure, DigitalOcean, Oracle, Alibaba, Kubernetes)
  - Protocol Smuggling (file://, gopher://, dict://, ftp://, ldap://)
- Service signature detection
- Admin panel detection
- SSRF detector registered in builtInDetectors.ts

### Missing Components
- InteractshClient implementation (currently just a stub)
- Configuration system support for SSRF detector options
- Unit tests for SSRF detector
- Integration tests for OOB functionality
- Documentation of SSRF capabilities
- CLI flags for SSRF configuration
- Example usage files

## Implementation Plan

### Phase 1: InteractshClient Implementation

Create src/core/network/InteractshClient.ts

Implement IOOBClient interface using ProjectDiscovery Interactsh API

Features:
- HTTP-based client for Interactsh server communication
- Payload generation with unique tracking IDs
- Polling mechanism for interaction detection
- Support for DNS, HTTP, SMTP interactions
- Error handling and retry logic
- Cleanup and resource management

### Phase 2: Configuration System Integration

Update src/types/config.ts

Add SsrfDetectorConfig interface to DetectorConfig

Update src/core/config/ConfigurationManager.ts

Parse and validate SSRF configuration options

Update src/utils/builtInDetectors.ts

Pass SSRF config to SsrfDetector constructor

Update src/cli/index.ts

Add CLI flags for SSRF configuration:
- --ssrf-oob
- --ssrf-oob-server
- --ssrf-waf-bypass
- --ssrf-cloud-metadata

### Phase 3: Testing

Create tests/unit/ssrf-detector.test.ts

Unit tests for SSRF detector:
- Payload generation tests
- Detection strategy tests
- Service signature detection tests
- Configuration tests

Create tests/unit/oob-client.test.ts

Unit tests for OOB clients:
- MockOOBClient tests
- InteractshClient tests

Create tests/integration/oob-ssrf.test.ts

Integration tests for OOB SSRF detection:
- Blind SSRF detection
- Multiple interaction types
- OOB with other strategies

### Phase 4: Documentation

Create docs/SSRF-DETECTOR.md

Comprehensive SSRF detector documentation

Update README.md

Add SSRF details and OOB detection information

Update docs/DEVELOPER-GUIDE.md

Add SSRF configuration section

Create examples/05-ssrf-oob-detection.ts

Example usage of OOB detection

## Implementation Priority

High Priority:
1. InteractshClient implementation
2. Configuration system integration
3. Unit tests for SSRF detector
4. Documentation update

Medium Priority:
1. Integration tests for OOB
2. CLI support for SSRF config
3. Example usage files
4. Error handling improvements

Low Priority:
1. Burp Collaborator client
2. Advanced telemetry
3. Custom OOB server implementation
4. OOB interaction visualization in reports

## Risk Assessment

Technical Risks:
- Interactsh API changes - mitigate with flexible HTTP client
- OOB service downtime - mitigate with fallback strategies
- Network issues - mitigate with timeouts and retries
- Performance impact - mitigate with polling optimization

Security Risks:
- Data exfiltration - mitigate by documenting OOB usage clearly
- Privacy concerns - mitigate by making OOB opt-in
- Credential exposure - mitigate with secure token handling

Operational Risks:
- Cost implications - mitigate by documenting private server requirements
- False positives - mitigate with confidence scoring
- False negatives - mitigate with multiple detection strategies

## Success Criteria

Functional Requirements:
- OOB detection works with MockOOBClient
- OOB detection works with Interactsh
- Configuration system supports SSRF options
- CLI flags for SSRF configuration
- Unit tests cover all detection strategies
- Integration tests validate OOB functionality

Non-Functional Requirements:
- OOB detection doesn't significantly impact scan performance
- OOB failures don't crash scan
- Documentation is comprehensive and clear
- Examples demonstrate all features
- Code follows project conventions

Quality Requirements:
- All new code has unit tests
- All new code is linted
- All new code is documented
- No breaking changes to existing API

## Next Steps

1. Review and approve this plan
2. Switch to Code mode to begin implementation
3. Start with Phase 1 (InteractshClient implementation)
4. Proceed through phases sequentially
5. Test thoroughly at each phase

## References

- OWASP SSRF: https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
- PortSwigger SSRF: https://portswigger.net/web-security/ssrf
- ProjectDiscovery Interactsh: https://github.com/projectdiscovery/interactsh
- Burp Collaborator: https://portswigger.net/burp/documentation/collaborator