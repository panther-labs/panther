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

import { Box, Flex, SimpleGrid, Link, Heading, Tooltip, Icon, Card } from 'pouncejs';
import urls from 'Source/urls';
import React from 'react';
import { RuleDetails } from 'Generated/schema';
import Linkify from 'Components/Linkify';
import { formatDatetime } from 'Helpers/utils';
import { Link as RRLink } from 'react-router-dom';
import SeverityBadge from 'Components/badges/SeverityBadge';
import UpdateAlertDropdown from 'Components/dropdowns/UpdateAlertDropdown';
import { AlertSummaryFull } from 'Source/graphql/fragments/AlertSummaryFull.generated';
import { AlertDetailsFull } from 'Source/graphql/fragments/AlertDetailsFull.generated';

interface AlertDetailsInfoProps {
  alert: AlertDetailsFull;
  rule: Partial<RuleDetails>;
}

const AlertDetailsInfo: React.FC<AlertDetailsInfoProps> = ({ alert, rule }) => {
  if (!rule) {
    return (
      <Card as="article" p={6}>
        <Flex as="header" align="center" mb={4} spacing={4}>
          <Heading fontWeight="bold" wordBreak="break-word">
            {alert.title || alert.alertId}
          </Heading>
          <Tooltip
            content={
              <Flex spacing={3}>
                <Box id="alert-id-label">Alert ID</Box>
                <Box aria-labelledby="alert-id-label" fontWeight="bold">
                  {alert.alertId}
                </Box>
              </Flex>
            }
          >
            <Icon type="info" />
          </Tooltip>
        </Flex>
        <Card variant="dark" as="section" p={4}>
          <SimpleGrid columns={2} spacing={5} fontSize="small-medium">
            <Flex spacing={5}>
              <Flex direction="column" spacing={2} color="navyblue-100" flexShrink={0}>
                <Box aria-describedby="rule-link">Rule</Box>
                <Box aria-describedby="deduplication-string">Deduplication String</Box>
              </Flex>
              <Flex direction="column" spacing={2}>
                <Box color="red-300">Associated rule has been deleted</Box>
                <Box id="deduplication-string">{alert.dedupString}</Box>
              </Flex>
            </Flex>
            <Flex spacing={60}>
              <Flex direction="column" color="navyblue-100" spacing={2}>
                <Box aria-describedby="created-at">Created</Box>
                <Box aria-describedby="last-matched-at">Last Matched</Box>
              </Flex>
              <Flex direction="column" spacing={2}>
                <Box id="created-at">{formatDatetime(alert.creationTime)}</Box>
                <Box id="last-matched-at">{formatDatetime(alert.updateTime)}</Box>
              </Flex>
            </Flex>
          </SimpleGrid>
        </Card>
      </Card>
    );
  }

  return (
    <Card as="article" p={6}>
      <Flex as="header" align="center" mb={4} spacing={4}>
        <Heading fontWeight="bold" wordBreak="break-word">
          {alert.title || alert.alertId}
        </Heading>
        <Tooltip
          content={
            <Flex spacing={3}>
              <Flex direction="column" spacing={2}>
                <Box id="alert-id-label">Alert ID</Box>
                <Box id="log-types-label">Log Types</Box>
              </Flex>
              <Flex direction="column" spacing={2} fontWeight="bold">
                <Box aria-labelledby="alert-id-label">{alert.alertId}</Box>
                <Box aria-labelledby="log-types-label">
                  {rule.logTypes.map(logType => (
                    <Box key={logType}>{logType}</Box>
                  ))}
                </Box>
              </Flex>
            </Flex>
          }
        >
          <Icon type="info" />
        </Tooltip>
      </Flex>
      <Flex spacing={4} as="ul" mb={6}>
        <Box as="li" aria-describedby="alert-status-description">
          <UpdateAlertDropdown alert={alert as AlertSummaryFull} />
        </Box>
        <Box as="li" aria-describedby="alert-severity-description">
          <SeverityBadge severity={rule.severity} />
        </Box>
      </Flex>
      <Card variant="dark" as="section" p={4} mb={4}>
        <SimpleGrid columns={2} spacing={5}>
          <Flex direction="column" spacing={2}>
            <Box
              color="navyblue-100"
              fontSize="small-medium"
              aria-describedby="runbook-description"
            >
              Runbook
            </Box>
            {rule.runbook ? (
              <Linkify id="runbook-description">{rule.runbook}</Linkify>
            ) : (
              <Box fontStyle="italic" color="navyblue-100" id="runbook-description">
                No runbook specified
              </Box>
            )}
          </Flex>
          <Flex direction="column" spacing={2}>
            <Box
              color="navyblue-100"
              fontSize="small-medium"
              aria-describedby="reference-description"
            >
              Reference
            </Box>
            {rule.reference ? (
              <Linkify id="reference-description">{rule.reference}</Linkify>
            ) : (
              <Box fontStyle="italic" color="navyblue-100" id="reference-description">
                No reference specified
              </Box>
            )}
          </Flex>
        </SimpleGrid>
      </Card>
      <Card variant="dark" as="section" p={4}>
        <SimpleGrid columns={2} spacing={5} fontSize="small-medium">
          <Flex spacing={5}>
            <Flex direction="column" spacing={2} color="navyblue-100" flexShrink={0}>
              <Box aria-describedby="rule-link">Rule</Box>
              <Box aria-describedby="tags-list">Tags</Box>
              <Box aria-describedby="deduplication-string">Deduplication String</Box>
            </Flex>
            <Flex direction="column" spacing={2}>
              <Link id="rule-link" as={RRLink} to={urls.logAnalysis.rules.details(rule.id)}>
                {rule.displayName || rule.id}
              </Link>
              {rule.tags.length > 0 ? (
                <Box id="tags-list">
                  {rule.tags.map((tag, index) => (
                    <Link
                      key={tag}
                      as={RRLink}
                      to={`${urls.logAnalysis.rules.list()}?page=1&tags[]=${tag}`}
                    >
                      {tag}
                      {index !== rule.tags.length - 1 ? ', ' : null}
                    </Link>
                  ))}
                </Box>
              ) : (
                <Box fontStyle="italic" color="navyblue-100" id="tags-list">
                  This rule has no tags
                </Box>
              )}
              <Box id="deduplication-string">{alert.dedupString}</Box>
            </Flex>
          </Flex>
          <Flex spacing={60}>
            <Flex direction="column" color="navyblue-100" spacing={2}>
              <Box aria-describedby="created-at">Created</Box>
              <Box aria-describedby="last-matched-at">Last Matched</Box>
            </Flex>
            <Flex direction="column" spacing={2}>
              <Box id="created-at">{formatDatetime(alert.creationTime)}</Box>
              <Box id="last-matched-at">{formatDatetime(alert.updateTime)}</Box>
            </Flex>
          </Flex>
        </SimpleGrid>
      </Card>
    </Card>
  );
};

export default AlertDetailsInfo;
