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
import { Box, Card, Flex, Heading, Link, SimpleGrid } from 'pouncejs';
import urls from 'Source/urls';
import { Link as RRLink } from 'react-router-dom';
import { formatDatetime } from 'Helpers/utils';
import { ComplianceIntegration, ResourceDetails } from 'Generated/schema';
import StatusBadge from 'Components/badges/StatusBadge';

interface ResourceDetailsInfoProps {
  resource?: ResourceDetails & Pick<ComplianceIntegration, 'integrationLabel'>;
}

const ResourceDetailsInfo: React.FC<ResourceDetailsInfoProps> = ({ resource }) => {
  return (
    <Card as="article" p={6}>
      <Flex as="header" align="center" mb={4} spacing={4}>
        <Heading fontWeight="bold" wordBreak="break-word">
          {resource.id}
        </Heading>
      </Flex>
      <Flex spacing={4} as="ul" mb={6}>
        <Box as="li">
          <StatusBadge status={resource.complianceStatus} />
        </Box>
      </Flex>
      <Card variant="dark" as="section" p={4}>
        <SimpleGrid columns={3} fontSize="small-medium">
          <Flex spacing={5}>
            <Box id="type-label" color="navyblue-100">
              Type
            </Box>
            <Link
              aria-labelledby="type-label"
              as={RRLink}
              to={`${urls.compliance.resources.list()}?types[]=${resource.type}`}
            >
              {resource.type}
            </Link>
          </Flex>
          <Flex spacing={5}>
            <Box id="source-label" color="navyblue-100">
              Source
            </Box>
            <Link
              aria-labelledby="source-label"
              as={RRLink}
              to={`${urls.compliance.resources.list()}?integrationId=${resource.integrationId}`}
            >
              {resource.integrationLabel}
            </Link>
          </Flex>
          <Flex spacing={5}>
            <Box id="updated-at" color="navyblue-100">
              Modified
            </Box>
            <Box id="updated-at">{formatDatetime(resource.lastModified)}</Box>
          </Flex>
        </SimpleGrid>
      </Card>
    </Card>
  );
};

export default React.memo(ResourceDetailsInfo);
