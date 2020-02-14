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

import React from 'react';
import { Text, Box, Heading } from 'pouncejs';
import { PANTHER_SCHEMA_DOCS_LINK } from 'Source/constants';

/*
https://s3-us-west-2.amazonaws.com/panther-public-cloudformation-templates/panther-cloudwatch-events/latest/template.yml
 */

const RealTimeEventPanel: React.FC = () => {
  return (
    <Box>
      <Heading size="medium" m="auto" mb={10} color="grey400">
        Setup Real-Time AWS Resource Scans (Optional)
      </Heading>
      <Text size="large" color="grey200" mb={6} is="p">
        To perform this step, visit our{' '}
        <a
          target="_blank"
          rel="noopener noreferrer"
          href={`${PANTHER_SCHEMA_DOCS_LINK}/amazon-web-services/aws-setup/real-time-events`}
        >
          documentation
        </a>{' '}
        and follow the steps described there.
      </Text>
    </Box>
  );
};

export default RealTimeEventPanel;
