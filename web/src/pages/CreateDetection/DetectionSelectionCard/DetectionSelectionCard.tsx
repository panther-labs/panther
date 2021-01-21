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
import {
  Box,
  Card,
  Flex,
  Heading,
  Icon,
  IconProps,
  Radio,
  Text,
  Theme,
  AbstractButton,
  Img,
} from 'pouncejs';
import useUrlParams from 'Hooks/useUrlParams';
import PantherEnterpriseLogo from 'Assets/panther-enterprise-minimal-logo.svg';
import { CreateDetectionUrlParams } from '../CreateDetection';

const noop = () => {};

interface DetectionSelectionCardProps {
  title: string;
  description: string;
  icon: IconProps['type'];
  iconColor: keyof Theme['colors'];
  type?: CreateDetectionUrlParams['type'];
  availableInEnterprise?: boolean;
}

const DetectionSelectionCard: React.FC<DetectionSelectionCardProps> = ({
  type,
  title,
  description,
  iconColor,
  icon,
  availableInEnterprise = false,
}) => {
  const { urlParams, setUrlParams } = useUrlParams<CreateDetectionUrlParams>();

  const isActive = urlParams.type === type;
  const content = (
    <Card p={4} variant={isActive ? 'light' : 'dark'}>
      <Flex>
        <Flex
          borderRadius="circle"
          height={32}
          width={32}
          justify="center"
          align="center"
          backgroundColor={iconColor}
          flexShrink={0}
          mr={4}
        >
          <Icon size="small" type={icon} />
        </Flex>
        <Box>
          <Flex align="center" justify="space-between" mt={-1} mr={-1}>
            <Heading as="h2" size="x-small">
              {title}
            </Heading>
            {availableInEnterprise ? (
              <Img
                nativeWidth={44}
                nativeHeight={44}
                p={3}
                alt="Panther Enterprise Logo"
                src={PantherEnterpriseLogo}
              />
            ) : (
              <Radio checked={isActive} onChange={noop} />
            )}
          </Flex>
          <Text fontSize="small" color="gray-300" textAlign="left">
            {description}
          </Text>
        </Box>
      </Flex>
    </Card>
  );

  if (availableInEnterprise) {
    return content;
  }

  return (
    <AbstractButton aria-label={`Create ${title}`} onClick={() => setUrlParams({ type })}>
      {content}
    </AbstractButton>
  );
};

export default DetectionSelectionCard;
