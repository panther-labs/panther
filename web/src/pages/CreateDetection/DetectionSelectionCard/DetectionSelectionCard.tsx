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
