/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

const { defaults } = require('jest-config');

module.exports = {
  // Only search for typescript tests
  rootDir: '../',
  testMatch: ['<rootDir>/**/*.test.{ts,tsx}'],

  // Allow searching for modules written in TS
  moduleFileExtensions: [...defaults.moduleFileExtensions, 'ts', 'tsx'],

  // This is the only way for jest to detect our custom webpack aliases
  moduleNameMapper: {
    '\\.(jpg|jpeg|png|svg)$': '<rootDir>/__tests__/__mocks__/file.ts',
    '^Assets/(.*)': '<rootDir>/src/assets/$1',
    '^Components/(.*)': '<rootDir>/src/components/$1',
    '^Generated/(.*)': '<rootDir>/__generated__/$1',
    '^Helpers/(.*)': '<rootDir>/src/helpers/$1',
    '^Pages/(.*)': '<rootDir>/src/pages/$1',
    '^Hooks/(.*)': '<rootDir>/src/hooks/$1',
    '^Hoc/(.*)': '<rootDir>/src/hoc/$1',
    '^Source/(.*)': '<rootDir>/src/$1',
    'test-utils': '<rootDir>/__tests__/utils',
  },

  // mocks sessionStorage & localStorage
  setupFiles: ['jest-localstorage-mock', 'jest-canvas-mock', '<rootDir>/__tests__/env.ts'],

  // additional browser API mocks & assertions
  setupFilesAfterEnv: ['<rootDir>/__tests__/setup.ts'],

  // report results for each file
  verbose: true,

  // Helps in the CLI by adding typeahead searches for filenames and testnames
  watchPlugins: ['jest-watch-typeahead/filename', 'jest-watch-typeahead/testname'],
};
