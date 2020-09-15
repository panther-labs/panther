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

import React from 'react';
import { Box, Card, Flex, Img, Link, SimpleGrid } from 'pouncejs';
import Linkify from 'Components/Linkify';
import { Link as RRLink } from 'react-router-dom';
import urls from 'Source/urls';
import { formatDatetime, minutesToString } from 'Helpers/utils';
import { AlertDetails, RuleTeaser, ListDestinations } from 'Pages/AlertDetails';
import AlertDeliverySection from 'Pages/AlertDetails/AlertDetailsInfo/AlertDeliverySection';
import { DESTINATIONS } from 'Source/constants';

interface AlertDetailsInfoProps {
  alert: AlertDetails['alert'];
  rule: RuleTeaser['rule'];
  configuredAlertDestinations: ListDestinations['destinations'];
}

const AlertDetailsInfo: React.FC<AlertDetailsInfoProps> = ({
  alert,
  rule,
  configuredAlertDestinations,
}) => {
  return (
    <Flex direction="column" spacing={4}>
      {rule && (
        <Card variant="dark" as="section" p={4}>
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
      )}
      <Card variant="dark" as="section" p={4}>
        <SimpleGrid columns={2} spacing={5} fontSize="small-medium">
          {rule ? (
            <Flex spacing={5}>
              <Flex direction="column" spacing={2} color="navyblue-100" flexShrink={0}>
                <Box aria-describedby="rule-link">Rule</Box>
                <Box aria-describedby="threshold">Rule Threshold</Box>
                <Box aria-describedby="deduplication-period">Deduplication Period</Box>
                <Box aria-describedby="deduplication-string">Deduplication String</Box>
                <Box aria-describedby="tags-list">Tags</Box>
              </Flex>
              <Flex direction="column" spacing={2}>
                <Link id="rule-link" as={RRLink} to={urls.logAnalysis.rules.details(rule.id)}>
                  {rule.displayName || rule.id}
                </Link>
                <Box id="threshold">{minutesToString(rule.threshold)}</Box>
                <Box id="deduplication-period">
                  {rule.dedupPeriodMinutes
                    ? minutesToString(rule.dedupPeriodMinutes)
                    : 'Not specified'}
                </Box>
                <Box id="deduplication-string">{alert.dedupString}</Box>
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
              </Flex>
            </Flex>
          ) : (
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
          )}
          <Flex spacing={60}>
            <Flex direction="column" color="navyblue-100" spacing={2}>
              <Box aria-describedby="created-at">Created</Box>
              <Box aria-describedby="last-matched-at">Last Matched</Box>
              <Box aria-describedby="destinations">Destinations</Box>
            </Flex>
            <Flex direction="column" spacing={2}>
              <Box id="created-at">{formatDatetime(alert.creationTime)}</Box>
              <Box id="last-matched-at">{formatDatetime(alert.updateTime)}</Box>
              <Box id="destinations">
                {configuredAlertDestinations.map(destination => {
                  const destData = DESTINATIONS[destination.outputType];
                  return (
                    <Flex key={destination.outputId} mb={2}>
                      <Img
                        alt={`${destination.outputType} logo`}
                        src={destData.logo}
                        nativeWidth={18}
                        nativeHeight={18}
                        mr={2}
                      />
                      {destData.title}
                    </Flex>
                  );
                })}
              </Box>
            </Flex>
          </Flex>
        </SimpleGrid>
      </Card>
      <Card variant="dark" as="section" p={4}>
        <AlertDeliverySection alert={alert} />
      </Card>
    </Flex>
  );
};

export default AlertDetailsInfo;
