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
  Critical: theme.colors['red-500'],
  High: theme.colors['orange-400'],
  Medium: theme.colors['yellow-500'],
  Low: theme.colors['gray-500'],
  Info: theme.colors['gray-600'],

  // FIXME: These should be mapped through pounce
  'AWS.ALB': theme.colors['indigo-800'],
  'AWS.VPCFlow': theme.colors['yellow-800'],
  'AWS.S3': theme.colors['green-300'],
  'AWS.S3ServerAccess': theme.colors['red-400'],
  'Apache.AccessCombined': theme.colors['navyblue-100'],
  'Apache.AccessCommon': theme.colors['blue-300'],
  'AWS.AuroraMySQLAudit': theme.colors['pink-500'],
  'AWS.CloudTrail': theme.colors['magenta-300'],
  'AWS.CloudTrailDigest': theme.colors['navyblue-200'],
  'AWS.CloudTrailInsight': theme.colors['magenta-700'],
  'AWS.CloudWatchEvents': theme.colors['blue-300'],
  'AWS.GuardDuty': theme.colors['blue-100'],
  'Fluentd.Syslog3164': theme.colors['indigo-500'],
  'Fluentd.Syslog5424': theme.colors['indigo-100'],
  'GitLab.API': theme.colors['yellow-500'],
  'GitLab.Audit': theme.colors['yellow-100'],
  'GitLab.Exceptions': theme.colors['orange-400'],
  'GitLab.Git': theme.colors['orange-200'],
  'GitLab.Integrations': theme.colors['orange-600'],
  'GitLab.Production': theme.colors['orange-800'],
  'Juniper.Access': theme.colors['purple-800'],
  'Juniper.Audit': theme.colors['purple-600'],
  'Juniper.Firewall': theme.colors['purple-300'],
  'Juniper.MWS': theme.colors['purple-200'],
  'Juniper.Postgres': theme.colors['magenta-100'],
  'Juniper.Security': theme.colors['magenta-300'],
  'Nginx.Access': theme.colors['green-100'],
  'Osquery.Batch': theme.colors['cyan-100'],
  'Osquery.Differential': theme.colors['cyan-200'],
  'Osquery.Snapshot': theme.colors['cyan-400'],
  'Osquery.Status': theme.colors['cyan-600'],
  'OSSEC.EventInfo': theme.colors['cyan-800'],
  'Suricata.Anomaly': theme.colors['pink-800'],
  'Suricata.DNS': theme.colors['pink-600'],
  'Syslog.RFC3164': theme.colors['violet-200'],
  'Syslog.RFC5424': theme.colors['violet-300'],
  'Zeek.DNS': theme.colors['blue-500'],
};
