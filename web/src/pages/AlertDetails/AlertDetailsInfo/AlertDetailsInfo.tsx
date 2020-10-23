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
import { Box, Card, Flex, Link, SimpleGrid } from 'pouncejs';
import Linkify from 'Components/Linkify';
import { Link as RRLink } from 'react-router-dom';
import urls from 'Source/urls';
import { formatDatetime, formatNumber, minutesToString } from 'Helpers/utils';
import { AlertDetails, RuleTeaser } from 'Pages/AlertDetails';
import AlertDeliverySection from 'Pages/AlertDetails/AlertDetailsInfo/AlertDeliverySection';
import RelatedDestinations from 'Components/RelatedDestinations';
import useAlertDestinations from 'Hooks/useAlertDestinations';

interface AlertDetailsInfoProps {
  alert: AlertDetails['alert'];
  rule: RuleTeaser['rule'];
}

const AlertDetailsInfo: React.FC<AlertDetailsInfoProps> = ({ alert, rule }) => {
  const { alertDestinations, loading: loadingDestinations } = useAlertDestinations({ alert });

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
          <Box>
            <SimpleGrid gap={2} columns={8} spacing={2}>
              {rule ? (
                <>
                  <Box color="navyblue-100" gridColumn="1/3" aria-describedby="rule-link">
                    Rule
                  </Box>

                  <Link
                    id="rule-link"
                    gridColumn="3/8"
                    as={RRLink}
                    to={urls.logAnalysis.rules.details(rule.id)}
                  >
                    {rule.displayName || rule.id}
                  </Link>

                  <Box color="navyblue-100" gridColumn="1/3" aria-describedby="threshold">
                    Rule Threshold
                  </Box>

                  <Box id="threshold" gridColumn="3/8">
                    {formatNumber(rule.threshold)}
                  </Box>

                  <Box
                    color="navyblue-100"
                    gridColumn="1/3"
                    aria-describedby="deduplication-period"
                  >
                    Deduplication Period
                  </Box>

                  <Box id="deduplication-period" gridColumn="3/8">
                    {rule.dedupPeriodMinutes
                      ? minutesToString(rule.dedupPeriodMinutes)
                      : 'Not specified'}
                  </Box>

                  <Box
                    color="navyblue-100"
                    gridColumn="1/3"
                    aria-describedby="deduplication-string"
                  >
                    Deduplication String
                  </Box>

                  <Box id="deduplication-string" gridColumn="3/8">
                    {alert.dedupString}
                  </Box>

                  <Box color="navyblue-100" gridColumn="1/3" aria-describedby="tags-list">
                    Tags
                  </Box>

                  {rule.tags.length > 0 ? (
                    <Box id="tags-list" gridColumn="3/8">
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
                    <Box fontStyle="italic" color="navyblue-100" id="tags-list" gridColumn="3/8">
                      This rule has no tags
                    </Box>
                  )}
                </>
              ) : (
                <>
                  <Box color="navyblue-100" gridColumn="1/3" aria-describedby="rule-link">
                    Rule
                  </Box>
                  <Box gridColumn="3/8" color="red-300">
                    Associated rule has been deleted
                  </Box>

                  <Box
                    color="navyblue-100"
                    gridColumn="1/3"
                    aria-describedby="deduplication-string"
                  >
                    Deduplication String
                  </Box>
                  <Box gridColumn="3/8" id="deduplication-string">
                    {alert.dedupString}
                  </Box>
                </>
              )}
            </SimpleGrid>
          </Box>

          <Box>
            <SimpleGrid gap={2} columns={8} spacing={2}>
              <Box color="navyblue-100" gridColumn="1/3" aria-describedby="created-at">
                Created
              </Box>

              <Box id="created-at" gridColumn="3/8">
                {formatDatetime(alert.creationTime)}
              </Box>

              <Box color="navyblue-100" gridColumn="1/3" aria-describedby="last-matched-at">
                Last Matched
              </Box>
              <Box gridColumn="3/8" id="last-matched-at">
                {formatDatetime(alert.updateTime)}
              </Box>

              <Box color="navyblue-100" gridColumn="1/3" aria-describedby="destinations">
                Destinations
              </Box>

              <Box id="destinations" gridColumn="3/8">
                <RelatedDestinations
                  destinations={alertDestinations}
                  loading={loadingDestinations}
                  verbose
                />
              </Box>
            </SimpleGrid>
          </Box>
        </SimpleGrid>
      </Card>
      <Card variant="dark" as="section" p={4}>
        <AlertDeliverySection alert={alert} alertDestinations={alertDestinations} />
      </Card>
    </Flex>
  );
};

export default AlertDetailsInfo;
