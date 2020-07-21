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

  // FIXME: These should be mapped through pounce
  'AWS.ALB': '#4e33e3',
  'AWS.VPCFlow': '#FF7577',
  'AWS.S3': '#92cb3e',
  'AWS.S3ServerAccess': '#C82727',
  'Apache.AccessCombined': '#86A3C3',
  'Apache.AccessCommon': '#11A5F3',
  'AWS.AuroraMySQLAudit': '#C55773',
  'AWS.CloudTrail': '#B81C77',
  'AWS.CloudTrailDigest': '#4F627C',
  'AWS.CloudTrailInsight': '#590134',
  'AWS.CloudWatchEvents': '#11A5F3',
  'AWS.GuardDuty': '#ACE2FF',
  'Fluentd.Syslog3164': '#5D6AC0',
  'Fluentd.Syslog5424': '#CED3Ec',
  'GitLab.API': '#FFA500',
  'GitLab.Audit': '#FFDD9B',
  'GitLab.Exceptions': '#EB522A',
  'GitLab.Git': '#FF7C5A',
  'GitLab.Integrations': '#9C3B21',
  'GitLab.Production': '#57291D',
  'Juniper.Access': '#43134C',
  'Juniper.Audit': '#5A2164',
  'Juniper.Firewall': '#9E51AB',
  'Juniper.MWS': '#AD64BA',
  'Juniper.Postgres': '#F652B1',
  'Juniper.Security': '#B81C77',
  'Nginx.Access': '#C9E3A1',
  'Osquery.Batch': '#A4F8FF',
  'Osquery.Differential': '#73F4FF',
  'Osquery.Snapshot': '#29BAC6',
  'Osquery.Status': '#007A84',
  'OSSEC.EventInfo': '#043C4D',
  'Suricata.Anomaly': '#662737',
  'Suricata.DNS': '#AC4A63',
  'Syslog.RFC3164': '#9F97CA',
  'Syslog.RFC5424': '#8178B3',
  'Zeek.DNS': '#0B5297',
};
