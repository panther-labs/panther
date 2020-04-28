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
import { css } from '@emotion/react';
import { Box, Card, Text } from 'pouncejs';

interface ItemCardProps {
  logo: string;
  title: string;
  onClick?: () => void;
}

const DestinationCard: React.FunctionComponent<ItemCardProps> = ({ logo, title, onClick }) => (
  <Card
    width={1}
    as="button"
    onClick={onClick}
    css={css`
      cursor: pointer;
      transition: transform 0.15s ease-in-out;
      &:hover {
        transform: scale3d(1.03, 1.03, 1.03);
      }
    `}
  >
    <Box height={92} px={10}>
      <img src={logo} alt={title} style={{ objectFit: 'contain' }} width="100%" height="100%" />
    </Box>
    <Box borderTopStyle="solid" borderTopWidth="1px" borderColor="grey50">
      <Text size="medium" px={4} py={3} color="grey500" textAlign="left">
        {title}
      </Text>
    </Box>
  </Card>
);

export default DestinationCard;
