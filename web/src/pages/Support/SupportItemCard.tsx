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
import { Card, Flex, Heading, Img, Text } from 'pouncejs';

type SupportItemPros = {
  title: string;
  subtitle: string;
  imgSrc: string;
  cta: React.ReactNode;
};

const SupportItemCard: React.FC<SupportItemPros> = ({ title, subtitle, imgSrc, cta }) => {
  return (
    <Card backgroundColor="navyblue-500" p={4}>
      <Flex spacing={6} mx={6}>
        <Flex justify="center" align="center">
          <Flex
            justify="center"
            align="center"
            width={75}
            height={75}
            backgroundColor="navyblue-350"
            borderRadius="circle"
            fontSize="2x-small"
            fontWeight="medium"
          >
            <Img
              src={imgSrc}
              alt="Panther Enterprise logo"
              objectFit="contain"
              nativeHeight={40}
              nativeWidth={40}
            />
          </Flex>
        </Flex>
        <Flex direction="column" spacing={2} justify="space-between" align="space-between">
          <Heading size="small" color="white-100">
            {title}
          </Heading>

          {subtitle && (
            <Text fontSize="small-medium" color="navyblue-100" mt={1}>
              {subtitle}
            </Text>
          )}
          {cta}
        </Flex>
      </Flex>
    </Card>
  );
};

export default SupportItemCard;
