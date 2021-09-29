import type {Config} from '@jest/types';

const config: Config.InitialOptions = {
  verbose: true,
  preset: "ts-jest",
  testEnvironment: "node",
  transform: {
    "\\.[jt]sx?$": "ts-jest"
  },
  testRegex: "(/__tests__/.*|(\\.|/)(test|spec))\\.(jsx?|tsx?)$",
  moduleFileExtensions: ["ts", "tsx", "js", "jsx", "json", "node"],
  coverageThreshold: {
    "global": {
      "branches": 75,
      "functions": 80,
      "lines": 90,
      "statements": 90
    }
  },
  coverageReporters: [
    "json",
    "lcov",
    "text",
    "clover"
  ],
  setupFiles: ['<rootDir>/jest.crypto-setup.js']
};
export default config;
