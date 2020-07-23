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
import { useTheme } from 'pouncejs';

export const LineColors = {
  Critical: 'red-500',
  High: 'orange-400',
  Medium: 'yellow-500',
  Low: 'gray-500',
  Info: 'gray-600',
  'AWS.ALB': 'indigo-800',
  'AWS.VPCFlow': 'yellow-800',
  'AWS.S3': 'green-300',
  'AWS.S3ServerAccess': 'red-400',
  'Apache.AccessCombined': 'navyblue-100',
  'Apache.AccessCommon': 'blue-300',
  'AWS.AuroraMySQLAudit': 'pink-500',
  'AWS.CloudTrail': 'magenta-300',
  'AWS.CloudTrailDigest': 'navyblue-200',
  'AWS.CloudTrailInsight': 'magenta-700',
  'AWS.CloudWatchEvents': 'blue-300',
  'AWS.GuardDuty': 'blue-100',
  'Fluentd.Syslog3164': 'indigo-500',
  'Fluentd.Syslog5424': 'indigo-100',
  'GitLab.API': 'yellow-500',
  'GitLab.Audit': 'yellow-100',
  'GitLab.Exceptions': 'orange-400',
  'GitLab.Git': 'orange-200',
  'GitLab.Integrations': 'orange-600',
  'GitLab.Production': 'orange-800',
  'Juniper.Access': 'purple-800',
  'Juniper.Audit': 'purple-600',
  'Juniper.Firewall': 'purple-300',
  'Juniper.MWS': 'purple-200',
  'Juniper.Postgres': 'magenta-100',
  'Juniper.Security': 'magenta-300',
  'Nginx.Access': 'green-100',
  'Osquery.Batch': 'cyan-100',
  'Osquery.Differential': 'cyan-200',
  'Osquery.Snapshot': 'cyan-400',
  'Osquery.Status': 'cyan-600',
  'OSSEC.EventInfo': 'cyan-800',
  'Suricata.Anomaly': 'pink-800',
  'Suricata.DNS': 'pink-600',
  'Syslog.RFC3164': 'violet-200',
  'Syslog.RFC5424': 'violet-300',
  'Zeek.DNS': 'blue-500',
};

/**
 * Helps save & restore form sessions when the user navigates away or closes the tab while making
 * changes
 */

function useLineColors() {
  const theme = useTheme();
  return Object.keys(LineColors).reduce((acc, key) => {
    return { ...acc, [key]: theme.colors[LineColors[key]] };
  }, {});
}

export default useLineColors;
