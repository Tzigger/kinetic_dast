/** @type {import('jest').Config} */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests'],
  testMatch: ['**/*.test.ts'],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/cli/**',
    '!src/plugins/examples/**',
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
  moduleNameMapper: {
    '^@core/(.*)$': '<rootDir>/src/core/$1',
    '^@scanners/(.*)$': '<rootDir>/src/scanners/$1',
    '^@detectors/(.*)$': '<rootDir>/src/detectors/$1',
    '^@reporters/(.*)$': '<rootDir>/src/reporters/$1',
    '^@utils/(.*)$': '<rootDir>/src/utils/$1',
    '^@types/(.*)$': '<rootDir>/src/types/$1',
    '^@plugins/(.*)$': '<rootDir>/src/plugins/$1',
    '^@cli/(.*)$': '<rootDir>/src/cli/$1',
  },
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
  verbose: true,
  testTimeout: 30000,
  testPathIgnorePatterns: [
    '/node_modules/',
    'tests/integration/phase2-comprehensive.test.ts',
    'tests/integration/phase3-active-scanner.test.ts'
  ]
};
