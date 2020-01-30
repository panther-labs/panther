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

import { Alert, Badge, Box, Grid, Label, Text, Flex } from 'pouncejs';
import { Link } from 'react-router-dom';
import urls from 'Source/urls';
import React from 'react';
import { AlertDetails, RuleDetails } from 'Generated/schema';
import Linkify from 'linkifyjs/react';
import { SEVERITY_COLOR_MAP } from 'Source/constants';
import { formatDatetime } from 'Helpers/utils';
import Panel from 'Components/panel';

interface AlertDetailsInfoProps {
  alert: AlertDetails;
  rule: Partial<RuleDetails>;
}

const AlertDetailsInfo: React.FC<AlertDetailsInfoProps> = ({ alert, rule }) => {
  if (!rule) {
    return (
      <Box>
        <Alert
          variant="info"
          title="Origin rule has been deleted"
          description="The rule that's responsible for this alert has been deleted and is no longer generating new alerts"
          mb={6}
        />
        <Panel size="large" title="Alert Details">
          <Grid gridTemplateColumns="repeat(3, 1fr)" gridGap={6}>
            <Box my={1}>
              <Label mb={1} is="div" size="small" color="grey300">
                ID
              </Label>
              <Text size="medium" color="black">
                {alert.alertId}
              </Text>
            </Box>
            <Box my={1}>
              <Label mb={1} is="div" size="small" color="grey300">
                RULE ORIGIN
              </Label>
              <Flex alignItems="center">
                <Text size="medium" color="black" mr={3}>
                  {alert.ruleId}
                </Text>
                <Badge color="pink">DELETED</Badge>
              </Flex>
            </Box>
            <Box my={1}>
              <Label mb={1} is="div" size="small" color="grey300">
                CREATED AT
              </Label>
              <Text size="medium" color="black">
                {formatDatetime(alert.creationTime)}
              </Text>
            </Box>
          </Grid>
        </Panel>
      </Box>
    );
  }

  return (
    <Panel size="large" title="Alert Details">
      <Grid gridTemplateColumns="repeat(3, 1fr)" gridGap={6}>
        <Box my={1}>
          <Label mb={1} is="div" size="small" color="grey300">
            ID
          </Label>
          <Text size="medium" color="black">
            {alert.alertId}
          </Text>
        </Box>
        <Box my={1}>
          <Label mb={1} is="div" size="small" color="grey300">
            RULE ORIGIN
          </Label>
          <Text size="medium" color="black">
            {<Link to={urls.rules.details(rule.id)}>{rule.displayName || rule.id}</Link> ||
              'No rule found'}
          </Text>
        </Box>
        <Box my={1}>
          <Label mb={1} is="div" size="small" color="grey300">
            LOG TYPES
          </Label>
          {rule.logTypes.length ? (
            rule.logTypes.map(logType => (
              <Text size="medium" color="black" key={logType}>
                {logType}
              </Text>
            ))
          ) : (
            <Text size="medium" color="black">
              All logs
            </Text>
          )}
        </Box>
        <Box my={1}>
          <Label mb={1} is="div" size="small" color="grey300">
            DESCRIPTION
          </Label>
          <Text size="medium" color={rule.description ? 'black' : 'grey200'}>
            <React.Suspense fallback={<span>{rule.description}</span>}>
              <Linkify>{rule.description || 'No description available'}</Linkify>
            </React.Suspense>
          </Text>
        </Box>
        <Box my={1}>
          <Label mb={1} is="div" size="small" color="grey300">
            RUNBOOK
          </Label>
          <Text size="medium" color={rule.runbook ? 'black' : 'grey200'}>
            <React.Suspense fallback={<span>{rule.runbook}</span>}>
              <Linkify>{rule.runbook || 'No runbook available'}</Linkify>
            </React.Suspense>
          </Text>
        </Box>
        <Box my={1}>
          <Label mb={1} is="div" size="small" color="grey300">
            SEVERITY
          </Label>
          <Badge color={SEVERITY_COLOR_MAP[rule.severity]}>{rule.severity}</Badge>
        </Box>
        <Box my={1}>
          <Label mb={1} is="div" size="small" color="grey300">
            TAGS
          </Label>
          {rule.tags.length ? (
            rule.tags.map((tag, index) => (
              <Text size="medium" color="black" key={tag} is="span">
                {tag}
                {index !== rule.tags.length - 1 ? ', ' : null}
              </Text>
            ))
          ) : (
            <Text size="medium" color="grey200">
              No tags assigned
            </Text>
          )}
        </Box>
        <Box my={1}>
          <Label mb={1} is="div" size="small" color="grey300">
            CREATED AT
          </Label>
          <Text size="medium" color="black">
            {formatDatetime(alert.creationTime)}
          </Text>
        </Box>
      </Grid>
    </Panel>
  );
};

export default AlertDetailsInfo;
