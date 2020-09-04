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
import { Link as RRLink } from 'react-router-dom';
import { Box, Button, Icon, SimpleGrid, Text, Link, Flex, Card, Heading, Tooltip } from 'pouncejs';
import { formatDatetime, minutesToString, formatNumber } from 'Helpers/utils';
import Linkify from 'Components/Linkify';
import { RuleDetails } from 'Generated/schema';
import urls from 'Source/urls';
import useModal from 'Hooks/useModal';
import { MODALS } from 'Components/utils/Modal';
import SeverityBadge from 'Components/badges/SeverityBadge';
import StatusBadge from 'Components/badges/StatusBadge';

interface ResourceDetailsInfoProps {
  rule?: RuleDetails;
}

const RuleDetailsInfo: React.FC<ResourceDetailsInfoProps> = ({ rule }) => {
  const { showModal } = useModal();

  return (
    <React.Fragment>
      <Flex spacing={4} mb={6} justify="flex-end">
        <Button as={RRLink} to={urls.logAnalysis.rules.edit(rule.id)}>
          Edit
        </Button>
        <Button
          variantColor="red"
          onClick={() =>
            showModal({
              modal: MODALS.DELETE_RULE,
              props: { rule },
            })
          }
        >
          Delete
        </Button>
      </Flex>
      <Card as="article" p={6}>
        <Flex as="header" align="center" mb={4} spacing={4}>
          <Heading fontWeight="bold" wordBreak="break-word" aria-describedby="rule-description">
            {rule.displayName || rule.id}
          </Heading>
          <Tooltip
            content={
              <Flex spacing={3}>
                <Flex direction="column" spacing={2}>
                  <Box id="rule-id-label">Rule ID</Box>
                  <Box id="log-types-label">Log Types</Box>
                </Flex>
                <Flex direction="column" spacing={2} fontWeight="bold">
                  <Box aria-labelledby="rule-id-label">{rule.id}</Box>
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
          <Box as="li">
            <StatusBadge status="ENABLED" disabled={!rule.enabled} />
          </Box>
          <Box as="li">
            <SeverityBadge severity={rule.severity} />
          </Box>
        </Flex>
        <Card variant="dark" as="section" p={4} mb={4}>
          <Text id="rule-description" fontStyle={!rule.description ? 'italic' : 'normal'} mb={6}>
            {rule.description || 'No description found for rule'}
          </Text>
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
                <Box aria-describedby="tags-list">Tags</Box>
                <Box aria-describedby="deduplication-period">Deduplication Period</Box>
                <Box aria-describedby="threshold">Threshold</Box>
              </Flex>
              <Flex direction="column" spacing={2}>
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
                <Box id="deduplication-period">{minutesToString(rule.dedupPeriodMinutes)}</Box>
                <Box id="threshold">{formatNumber(rule.threshold)}</Box>
              </Flex>
            </Flex>
            <Flex spacing={60}>
              <Flex direction="column" color="navyblue-100" spacing={2}>
                <Box aria-describedby="created-at">Created</Box>
                <Box aria-describedby="updated-at">Modified</Box>
              </Flex>
              <Flex direction="column" spacing={2}>
                <Box id="created-at">{formatDatetime(rule.createdAt)}</Box>
                <Box id="updated-at">{formatDatetime(rule.lastModified)}</Box>
              </Flex>
            </Flex>
          </SimpleGrid>
        </Card>
      </Card>
    </React.Fragment>
  );
};

export default React.memo(RuleDetailsInfo);
