/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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
   * Run prettier TS, JS, JSON, YAML and Markdown files found anywhere in the project
   */
  '*.{ts,tsx,js,md,yaml,yml,json}': ['prettier --write'],

  /*
   * Run ESLint checks for all TS & JS files found anywhere in hte project
   */
  '*.{ts,tsx,js}': ['eslint --config web/.eslintrc.js'],

  /*
   * only run the TS compiler when there are changes inTS files
   */
  '*.ts?(x)': () => 'tsc -p web',
};
