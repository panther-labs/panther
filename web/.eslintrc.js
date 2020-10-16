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

const path = require('path');

module.exports = {
  extends: [
    'airbnb-base', // Use Airbnb's eslinting rule for this project https://github.com/airbnb/javascript/tree/master/packages/eslint-config-airbnb-base
    'plugin:react/recommended',
    'plugin:@typescript-eslint/recommended',
    'prettier/@typescript-eslint',
    'plugin:prettier/recommended',
  ],
  env: {
    jest: true,
    browser: true,
    node: true,
  },
  ignorePatterns: ['npm-debug.log*', 'dist', '__generated__', '*.generated.*', 'codegen/*.js'],
  rules: {
    'import/prefer-default-export': 0,
    'max-len': 0,
    'no-unused-vars': 'off',
    'no-underscore-dangle': 'off',
    'no-console': 'error',
    curly: ['error', 'all'],
    'react/jsx-filename-extension': 0,
    'react/prop-types': 0,
    'import/no-extraneous-dependencies': 0,
    '@typescript-eslint/no-var-requires': 0,
    '@typescript-eslint/no-empty-function': 0,
    '@typescript-eslint/ban-ts-comment': 0,
    '@typescript-eslint/explicit-function-return-type': 0,
    '@typescript-eslint/no-explicit-any': 0,
    '@typescript-eslint/explicit-member-accessibility': 0,
    '@typescript-eslint/explicit-module-boundary-types': 0,
    '@typescript-eslint/no-unused-vars': [
      'error',
      {
        vars: 'all',
        args: 'after-used',
        ignoreRestSiblings: true,
      },
    ],
    'import/extensions': [
      'error',
      'always',
      {
        ts: 'never',
        tsx: 'never',
        js: 'never',
      },
    ],
  },
  plugins: ['@typescript-eslint'],
  settings: {
    'import/resolver': {
      webpack: {
        config: path.resolve(__dirname, 'webpack.config.js'),
      },
      alias: {
        map: [['test-utils', path.resolve(__dirname, '__tests__/utils')]],
        extensions: ['.ts', '.tsx'],
      },
    },
    react: {
      pragma: 'React',
      version: 'detect',
    },
  },
  parser: '@typescript-eslint/parser',
};
