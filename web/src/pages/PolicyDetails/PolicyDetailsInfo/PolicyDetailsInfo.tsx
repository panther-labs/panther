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
import { Box, SimpleGrid, Text, Link, Flex, Card } from 'pouncejs';
import { formatDatetime } from 'Helpers/utils';
import Linkify from 'Components/Linkify';
import { PolicyDetails } from 'Source/graphql/fragments/PolicyDetails.generated';
import urls from 'Source/urls';

interface ResourceDetailsInfoProps {
  policy?: PolicyDetails;
}

const PolicyDetailsInfo: React.FC<ResourceDetailsInfoProps> = ({ policy }) => {
  return (
    <Card as="article" p={6}>
      <Card variant="dark" as="section" p={4} mb={4}>
        <Text id="policy-description" fontStyle={!policy.description ? 'italic' : 'normal'} mb={6}>
          {policy.description || 'No description found for policy'}
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
            {policy.runbook ? (
              <Linkify id="runbook-description">{policy.runbook}</Linkify>
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
            {policy.reference ? (
              <Linkify id="reference-description">{policy.reference}</Linkify>
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
          <Box>
            <SimpleGrid gap={2} columns={8} spacing={2}>
              <Box gridColumn="1/3" color="navyblue-100" aria-describedby="tags-list">
                Tags
              </Box>
              {policy.tags.length > 0 ? (
                <Box gridColumn="3/8" id="tags-list">
                  {policy.tags.map((tag, index) => (
                    <Link
                      key={tag}
                      as={RRLink}
                      to={`${urls.detections.list()}?page=1&tags[]=${tag}`}
                    >
                      {tag}
                      {index !== policy.tags.length - 1 ? ', ' : null}
                    </Link>
                  ))}
                </Box>
              ) : (
                <Box fontStyle="italic" color="navyblue-100" gridColumn="3/8" id="tags-list">
                  This policy has no tags
                </Box>
              )}

              <Box gridColumn="1/3" color="navyblue-100" aria-describedby="ignore-patterns-list">
                Ignore Pattens
              </Box>
              {policy.suppressions.length > 0 ? (
                <Box gridColumn="3/8" id="ignore-patterns-list">
                  {policy.suppressions?.length > 0 ? policy.suppressions.join(', ') : null}
                </Box>
              ) : (
                <Box gridColumn="3/8" id="ignore-patterns-list">
                  No particular resource is ignored for this policy
                </Box>
              )}
            </SimpleGrid>
          </Box>
          <Box>
            <SimpleGrid gap={2} columns={8} spacing={2}>
              <Box gridColumn="1/3" color="navyblue-100" aria-describedby="created-at">
                Created
              </Box>
              <Box gridColumn="3/8" id="created-at">
                {formatDatetime(policy.createdAt)}
              </Box>

              <Box gridColumn="1/3" color="navyblue-100" aria-describedby="updated-at">
                Modified
              </Box>
              <Box gridColumn="3/8" id="updated-at">
                {formatDatetime(policy.lastModified)}
              </Box>
            </SimpleGrid>
          </Box>
        </SimpleGrid>
      </Card>
    </Card>
  );
};

export default React.memo(PolicyDetailsInfo);
