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
import { theme } from 'pouncejs';

export const LineColors = {
  // Alerts severity line colors
  Critical: theme.colors['red-400'],
  High: theme.colors['orange-500'],
  Medium: theme.colors['yellow-500'],
  Low: theme.colors['gray-500'],
  Info: theme.colors['gray-800'],

  'AWS.Cloudtrail': '#FDCA00',
  'AWS.ALB': '#4e33e3',
  'AWS.VPCFlow': '#dd4444',
  'AWS.S3': '#92cb3e',
};
