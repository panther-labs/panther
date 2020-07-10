const { defaults } = require('jest-config');

module.exports = {
  testMatch: ['<rootDir>/**/*.test.{ts,tsx}'],

  // Allow searching for modules written in TS
  moduleFileExtensions: [...defaults.moduleFileExtensions, 'ts', 'tsx'],

  // This is the only way for jest to detect our custom webpack aliases
  moduleNameMapper: {
    '\\.(jpg|jpeg|png|svg)$': '<rootDir>/__mocks__/fileMock.ts',
    '^lodash-es/(.*)': 'lodash/$1',
    '^Assets/(.*)': '<rootDir>/../src/assets/$1',
    '^Components/(.*)': '<rootDir>/../src/components/$1',
    '^Generated/(.*)': '<rootDir>/../__generated__/$1',
    '^Helpers/(.*)': '<rootDir>/../src/helpers/$1',
    '^Pages/(.*)': '<rootDir>/../src/pages/$1',
    '^Hooks/(.*)': '<rootDir>/../src/hooks/$1',
    '^Hoc/(.*)': '<rootDir>/../src/hoc/$1',
    '^Source/(.*)': '<rootDir>/../src/$1',
    'test-utils': '<rootDir>/utils',
  },

  // mocks sessionStorage & localStorage
  setupFiles: ['jest-localstorage-mock'],

  // additional browser API mocks & assertions
  setupFilesAfterEnv: ['<rootDir>/setup.ts'],

  // report results for each file
  verbose: true,

  // Helps in the CLI by adding typeahead searches for filenames and testnames
  watchPlugins: ['jest-watch-typeahead/filename', 'jest-watch-typeahead/testname'],
};
