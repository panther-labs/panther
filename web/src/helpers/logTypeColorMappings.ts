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

import mapKeys from 'lodash/mapKeys';
import { capitalize } from 'Helpers/utils';
import { Theme } from 'pouncejs';
import { LOG_TYPES, SEVERITY_COLOR_MAP } from 'Source/constants';

const severityColors = mapKeys(SEVERITY_COLOR_MAP, (val, key) => capitalize(key.toLowerCase()));

const logTypeColorMappings: Record<typeof LOG_TYPES[number], keyof Theme['colors']> = {
  'AWS.ALB': 'teal-100',
  'AWS.VPCFlow': 'orange-100',
  'AWS.S3ServerAccess': 'red-300',
  'Apache.AccessCombined': 'navyblue-100',
  'Apache.AccessCommon': 'teal-500',
  'AWS.AuroraMySQLAudit': 'pink-500',
  'AWS.CloudTrail': 'magenta-300',
  'AWS.CloudTrailDigest': 'purple-100',
  'AWS.CloudTrailInsight': 'violet-100',
  'AWS.CloudWatchEvents': 'blue-300',
  'AWS.GuardDuty': 'indigo-100',
  'Fluentd.Syslog3164': 'indigo-500',
  'Fluentd.Syslog5424': 'blue-100',
  'GitLab.API': 'yellow-500',
  'GitLab.Audit': 'yellow-100',
  'GitLab.Exceptions': 'teal-300',
  'GitLab.Git': 'cyan-300',
  'GitLab.Integrations': 'red-100',
  'GitLab.Production': 'gray-100',
  'Juniper.Access': 'indigo-300',
  'Juniper.Audit': 'gray-300',
  'Juniper.Firewall': 'purple-300',
  'Juniper.MWS': 'pink-300',
  'Juniper.Postgres': 'magenta-100',
  'Juniper.Security': 'red-500',
  'Nginx.Access': 'green-100',
  'Osquery.Batch': 'cyan-100',
  'Osquery.Differential': 'orange-500',
  'Osquery.Snapshot': 'pink-100',
  'Osquery.Status': 'gray-500',
  'OSSEC.EventInfo': 'green-500',
  'Suricata.Anomaly': 'cyan-500',
  'Suricata.DNS': 'navyblue-500',
  'Syslog.RFC3164': 'violet-500',
  'Syslog.RFC5424': 'violet-300',
  'Zeek.DNS': 'blue-500',
  'Gravitational.TeleportAudit': 'green-300',
  'Lacework.Events': 'green-700',
};

export default {
  ...severityColors,
  ...logTypeColorMappings,
};
