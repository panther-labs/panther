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
import { Box, Flex, Heading, Card, Label } from 'pouncejs';

interface PanelProps {
  title: string;
  size: 'small' | 'large';
  actions?: React.ReactNode;
}

const Panel: React.FC<PanelProps> = ({ title, actions, size, children }) => {
  return (
    <Card
      as="section"
      width={1}
      borderBottom="1px solid"
      borderColor="grey100"
      p={size === 'large' ? 8 : 6}
    >
      <Flex
        pb={size === 'large' ? 8 : 6}
        borderBottom="1px solid"
        borderColor="grey100"
        justify="space-between"
        align="center"
      >
        {size === 'large' ? (
          <Heading size="medium" as="h2">
            {title}
          </Heading>
        ) : (
          <Label size="large" as="h4">
            {title}
          </Label>
        )}
        {actions}
      </Flex>
      <Box mt={size === 'large' ? 8 : 6}>{children}</Box>
    </Card>
  );
};

export default Panel;
