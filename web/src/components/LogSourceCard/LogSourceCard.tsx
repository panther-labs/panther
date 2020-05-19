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

import * as React from 'react';
import { Badge, Box, Card, Flex, Icon, PseudoBox, Text } from 'pouncejs';
import { Link as RRLink } from 'react-router-dom';

interface ItemCardProps {
  logo: string;
  title: string;
  disabled?: boolean;
  to: string;
}

const LogSourceCard: React.FC<ItemCardProps> = ({ logo, title, to, disabled }) => {
  const content = (
    <PseudoBox
      width={1}
      as={'button'}
      mb={5}
      cursor="pointer"
      transition="transform 0.15s ease-in-out;"
      _hover={{
        transform: 'scale3d(1.03, 1.03, 1.03)',
        // @ts-ignore
        '#log-source-chevron-right': {
          opacity: '1',
        },
      }}
    >
      <Card width={1}>
        <Flex direction="row" justify="space-between" alignItems="center">
          <Flex direction="row" justifyContent="center" alignItems="center">
            <Box
              as="img"
              src={logo}
              alt={title}
              objectFit="contain"
              height={92}
              width={120}
              px={10}
              py={2}
            />
            <Text size="large" px={4} py={3} color="grey500" textAlign="center">
              {title}
            </Text>
          </Flex>
          {disabled ? (
            <Box mr={4}>
              <Badge color="blue">Coming Soon</Badge>
            </Box>
          ) : (
            <Flex justifyContent="center" alignItems="center">
              <Box id="log-source-chevron-right" opacity={0} px={10} py={2}>
                <Icon type="chevron-right" />
              </Box>
            </Flex>
          )}
        </Flex>
      </Card>
    </PseudoBox>
  );
  if (disabled) {
    return content;
  }
  return <RRLink to={to}>{content}</RRLink>;
};

export default LogSourceCard;
