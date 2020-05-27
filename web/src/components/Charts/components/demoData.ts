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

// TODO: Remove this from version control
export const demoData = {
  'AWS.ALB': {
    points: [
      {
        timestamp: '5/14',
        count: 10,
      },
      {
        timestamp: '5/15',
        count: 50,
      },
      {
        timestamp: '5/16',
        count: 13,
      },
      {
        timestamp: '5/17',
        count: 9,
      },
      {
        timestamp: '5/18',
        count: 9,
      },
      {
        timestamp: '5/19',
        count: 32,
      },
      {
        timestamp: '5/20',
        count: 42,
      },
    ],
  },
  'AWS.Cloudtrail': {
    points: [
      {
        timestamp: '5/14',
        count: 0,
      },
      {
        timestamp: '5/15',
        count: 8,
      },
      {
        timestamp: '5/16',
        count: 3,
      },
      {
        timestamp: '5/17',
        count: 0,
      },
      {
        timestamp: '5/18',
        count: 25,
      },
      {
        timestamp: '5/19',
        count: 6,
      },
      {
        timestamp: '5/20',
        count: 0,
      },
    ],
  },
  'Okta.SystemLogs': {
    points: [
      {
        timestamp: '5/14',
        count: 85,
      },
      {
        timestamp: '5/15',
        count: 63,
      },
      {
        timestamp: '5/16',
        count: 122,
      },
      {
        timestamp: '5/17',
        count: 87,
      },
      {
        timestamp: '5/18',
        count: 32,
      },
      {
        timestamp: '5/19',
        count: 5,
      },
      {
        timestamp: '5/20',
        count: 4,
      },
    ],
  },
};
