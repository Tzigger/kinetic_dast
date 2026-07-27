/**
 * Example unit test for Logger
 */

import { Logger } from '../../src/utils/logger/Logger';
import { LogLevel } from '../../src/types/enums';

describe('Logger', () => {
  let logger: Logger;

  beforeEach(() => {
    logger = new Logger(LogLevel.INFO);
  });

  describe('constructor', () => {
    it('should create logger with default log level', () => {
      const defaultLogger = new Logger();
      expect(defaultLogger.getLevel()).toBe(LogLevel.INFO);
    });

    it('should create logger with custom log level', () => {
      const debugLogger = new Logger(LogLevel.DEBUG);
      expect(debugLogger.getLevel()).toBe(LogLevel.DEBUG);
    });
  });

  describe('setLevel', () => {
    it('should update log level', () => {
      logger.setLevel(LogLevel.ERROR);
      expect(logger.getLevel()).toBe(LogLevel.ERROR);
    });
  });

  describe('child', () => {
    it('should create child logger with prefix', () => {
      const child = logger.child('TestModule');
      expect(child).toBeInstanceOf(Logger);
    });

    it('should inherit parent log level', () => {
      logger.setLevel(LogLevel.DEBUG);
      const child = logger.child('TestModule');
      expect(child.getLevel()).toBe(LogLevel.DEBUG);
    });
  });

  describe('logging methods', () => {
    it('should call error method', () => {
      const consoleSpy = jest.spyOn(console, 'error');
      logger.error('Test error');
      expect(consoleSpy).toHaveBeenCalled();
    });

    it('should call warn method when level allows', () => {
      const consoleSpy = jest.spyOn(console, 'warn');
      logger.warn('Test warning');
      expect(consoleSpy).toHaveBeenCalled();
    });

    it('should not log debug when level is INFO', () => {
      const consoleSpy = jest.spyOn(console, 'log');
      logger.setLevel(LogLevel.INFO);
      logger.debug('Debug message');
      expect(consoleSpy).not.toHaveBeenCalled();
    });

    it('should route logs to stderr in MCP mode', () => {
      process.env.KINETIC_MCP_MODE = 'true';
      const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => undefined);
      const logSpy = jest.spyOn(console, 'log').mockImplementation(() => undefined);

      const mcpLogger = new Logger(LogLevel.INFO);
      mcpLogger.info('MCP message');

      expect(errorSpy).toHaveBeenCalled();
      expect(logSpy).not.toHaveBeenCalled();

      delete process.env.KINETIC_MCP_MODE;
      errorSpy.mockRestore();
      logSpy.mockRestore();
    });
  });
});
