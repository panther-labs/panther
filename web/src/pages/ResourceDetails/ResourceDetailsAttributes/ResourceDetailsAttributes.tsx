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
import { Box, Card, Flex, IconButton } from 'pouncejs';
import JsonViewer from 'Components/JsonViewer';
import Panel from 'Components/Panel';
import { ComplianceIntegration, ResourceDetails } from 'Generated/schema';

interface ResourceDetailsAttributesProps {
  resource?: ResourceDetails & Pick<ComplianceIntegration, 'integrationLabel'>;
}

const ResourceDetailsAttributes: React.FC<ResourceDetailsAttributesProps> = ({ resource }) => {
  const [open, setOpen] = React.useState(true);
  return (
    <Panel title="Attributes">
      <Card p={4} variant="dark">
        <Flex align={open ? 'flex-start' : 'center'} spacing={open ? 7 : 2}>
          <IconButton
            variant="ghost"
            variantBorderStyle="circle"
            size="medium"
            active={open}
            variantColor="navyblue"
            icon={open ? 'caret-up' : 'caret-down'}
            onClick={() => setOpen(!open)}
            aria-label="Toggle attributes visibility"
          />

          {open ? (
            <JsonViewer data={JSON.parse(resource.attributes)} />
          ) : (
            <Box as="span" fontSize="small" color="gray-300">
              Click to expand
            </Box>
          )}
        </Flex>
      </Card>
    </Panel>
  );
};

export default ResourceDetailsAttributes;
