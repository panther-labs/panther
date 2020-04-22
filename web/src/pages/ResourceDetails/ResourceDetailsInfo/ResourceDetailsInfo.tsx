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
import { Box, Label, SimpleGrid, Text } from 'pouncejs';
import Panel from 'Components/Panel';
import { capitalize, formatDatetime } from 'Helpers/utils';
import { ComplianceStatusEnum, ComplianceIntegration, ResourceDetails } from 'Generated/schema';

interface ResourceDetailsInfoProps {
  resource?: ResourceDetails & Pick<ComplianceIntegration, 'integrationLabel'>;
}

const ResourceDetailsInfo: React.FC<ResourceDetailsInfoProps> = ({ resource }) => {
  return (
    <Panel size="large" title="Resource Details">
      <SimpleGrid columns={3} spacing={6}>
        <Box my={1}>
          <Label mb={1} as="div" size="small" color="grey300">
            ID
          </Label>
          <Text size="medium" color="black">
            {resource.id}
          </Text>
        </Box>
        <Box my={1}>
          <Label mb={1} as="div" size="small" color="grey300">
            TYPE
          </Label>
          <Text size="medium" color="black">
            {resource.type}
          </Text>
        </Box>
        <Box my={1}>
          <Label mb={1} as="div" size="small" color="grey300">
            SOURCE
          </Label>
          <Text size="medium" color="black">
            {resource.integrationLabel}
          </Text>
        </Box>
        <Box my={1}>
          <Label mb={1} as="div" size="small" color="grey300">
            STATUS
          </Label>
          <Text
            size="medium"
            color={resource.complianceStatus === ComplianceStatusEnum.Pass ? 'green300' : 'red300'}
          >
            {capitalize(resource.complianceStatus.toLowerCase())}
          </Text>
        </Box>
        <Box my={1}>
          <Label mb={1} as="div" size="small" color="grey300">
            LAST MODIFIED
          </Label>
          <Text size="medium" color="black">
            {formatDatetime(resource.lastModified)}
          </Text>
        </Box>
      </SimpleGrid>
    </Panel>
  );
};

export default React.memo(ResourceDetailsInfo);
