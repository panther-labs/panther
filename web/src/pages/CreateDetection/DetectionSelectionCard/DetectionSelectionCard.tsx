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
} from 'pouncejs';
import useUrlParams from 'Hooks/useUrlParams';
import { CreateDetectionUrlParams } from '../CreateDetection';

const noop = () => {};

interface DetectionSelectionCardProps {
  type: CreateDetectionUrlParams['type'];
  title: string;
  description: string;
  icon: IconProps['type'];
  iconColor: keyof Theme['colors'];
}

const DetectionSelectionCard: React.FC<DetectionSelectionCardProps> = ({
  type,
  title,
  description,
  iconColor,
  icon,
}) => {
  const { urlParams, setUrlParams } = useUrlParams<CreateDetectionUrlParams>();

  const isActive = urlParams.type === type;
  return (
    <AbstractButton onClick={() => setUrlParams({ type })}>
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
              <Radio checked={isActive} onChange={noop} />
            </Flex>
            <Text fontSize="small" color="gray-300" textAlign="left">
              {description}
            </Text>
          </Box>
        </Flex>
      </Card>
    </AbstractButton>
  );
};

export default DetectionSelectionCard;
