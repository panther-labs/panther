/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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

module.exports = {
  /*
   * Lint staged doesn't allow for multiple (comma separated) globs, so we have to split them
   * in multiple lines (or use a custom function to isolate files which adds more complexity)
   */

  /*
   * Run prettier on:
   * 1. All JSON/YAML inside the /web dir
   * 2. All JSON/YAML found in the root project dir
   * 3. All TS, JS and Markdown files found anywhere in the project
   */
  'web/**/*.{json,yml}': ['prettier --write', 'git add'],
  './*.{json,yml}': ['prettier --write', 'git add'],
  '*.{ts,tsx,js,md}': ['prettier --write', 'git add'],

  /*
   * Run ESLint checks for all TS & JS files found anywhere in hte project
   */
  '*.{ts,tsx,js}': ['eslint'],

  /*
   * only run the TS compiler when there are changes inTS files
   */
  '**/*.ts?(x)': () => 'tsc -p .',
};
