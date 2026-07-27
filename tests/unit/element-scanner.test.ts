import { Page } from 'playwright';
import { IActiveDetector } from '../../src/core/interfaces/IActiveDetector';
import { ElementScanner } from '../../src/scanners/active/ElementScanner';
import { AttackSurfaceType, InjectionContext } from '../../src/scanners/active/DomExplorer';
import { ElementScanConfig } from '../../src/types/element-scan';

describe('ElementScanner', () => {
  it('forwards safe mode to targeted active detectors', async () => {
    const elementHandle = {
      evaluate: jest.fn().mockResolvedValue({
        formAction: undefined,
        formMethod: 'post',
        inputType: 'text',
        otherFields: {},
      }),
    };
    const locator = {
      elementHandle: jest.fn().mockResolvedValue(elementHandle),
      first: jest.fn(function () {
        return this;
      }),
      inputValue: jest.fn().mockResolvedValue(''),
    };
    const page = {
      locator: jest.fn(() => locator),
    } as unknown as Page;
    const detect = jest.fn().mockResolvedValue([]);
    const detector: IActiveDetector = {
      analyzeInjectionResult: jest.fn().mockResolvedValue([]),
      detect,
      getPayloads: jest.fn().mockReturnValue([]),
      name: 'Test SQL Injection Detector',
      validate: jest.fn().mockResolvedValue(true),
    };
    const config: ElementScanConfig = {
      baseUrl: 'http://example.test',
      elements: [
        {
          context: InjectionContext.SQL,
          locator: '#target',
          name: 'Target',
          type: AttackSurfaceType.FORM_INPUT,
        },
      ],
      safeMode: true,
      skipNavigation: true,
    };
    const scanner = new ElementScanner(config);
    scanner.registerDetector(detector);
    await scanner.initialize({ config: {} as never, page } as never);

    await scanner.execute();

    expect(detect).toHaveBeenCalledWith(
      expect.objectContaining({
        attackSurfaces: [expect.objectContaining({ selector: '#target' })],
        safeMode: true,
      })
    );
  });
});
