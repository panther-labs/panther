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
import { Box, Card, Flex, Icon, IconProps, Label } from 'pouncejs';
import ErrorBoundary from 'Components/error-boundary';

interface DonutChartWrapperProps {
  title: string;
  icon: IconProps['type'];
}

const DonutChartWrapper: React.FC<DonutChartWrapperProps> = ({ children, title, icon }) => (
  <Card p={6} height={340}>
    <Flex alignItems="center" is="header" mb={6} color="grey500">
      <Icon size="small" type={icon} mr={4} />
      <Label size="large" is="h4">
        {title}
      </Label>
    </Flex>
    <Box height={250}>
      <ErrorBoundary>{children}</ErrorBoundary>
    </Box>
  </Card>
);

export default DonutChartWrapper;
