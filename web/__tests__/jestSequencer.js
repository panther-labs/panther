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

const Sequencer = require('@jest/test-sequencer').default;

/* eslint-disable */
class CustomSequencer extends Sequencer {
  sort(tests) {
    if (process.env.CIRCLE_NODE_TOTAL) {
      // In CI, parallelize tests across multiple tasks.
      const nodeTotal = parseInt(process.env.CIRCLE_NODE_TOTAL, 10);
      const nodeIndex = parseInt(process.env.CIRCLE_NODE_INDEX, 10);
      tests = tests
        .sort((a, b) => (a.path < b.path ? -1 : 1))
        .filter((_, i) => i % nodeTotal === nodeIndex);
    }
    return tests;
  }
}

/* eslint-enable */

module.exports = CustomSequencer;
