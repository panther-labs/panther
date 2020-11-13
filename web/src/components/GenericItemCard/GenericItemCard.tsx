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
import { Box, Card, Flex, IconButton, Img, Text, TextProps, Theme } from 'pouncejs';
import { slugify } from 'Helpers/utils';

interface GenericItemCardProps {
  borderColor?: keyof Theme['colors'];
}

interface GenericItemCardLogoProps {
  src: string;
}

interface GenericItemCardValueProps {
  id?: string;
  label?: string;
  value: string | number | React.ReactElement;
}

interface GenericItemCardComposition {
  Logo: React.FC<GenericItemCardLogoProps>;
  Heading: React.FC<TextProps>;
  Body: React.FC;
  Options: React.ForwardRefExoticComponent<React.RefAttributes<HTMLButtonElement>>;
  Value: React.FC<GenericItemCardValueProps>;
  ValuesGroup: React.FC;
  LineBreak: React.FC;
}

const GenericItemCard: React.FC<GenericItemCardProps> & GenericItemCardComposition = ({
  children,
  borderColor,
}) => {
  const statusProps = borderColor
    ? {
        borderLeft: '4px solid',
        borderColor,
      }
    : {};
  return (
    <Card as="section" variant="dark" p={5} {...statusProps} overflow="hidden">
      <Box>
        <Flex position="relative" height="100%">
          {children}
        </Flex>
      </Box>
    </Card>
  );
};

const GenericItemCardHeading: React.FC<TextProps> = ({ children, ...rest }) => {
  return (
    <Text fontWeight="medium" wordBreak="break-word" as="h4" {...rest}>
      {children}
    </Text>
  );
};

const GenericItemCardBody: React.FC = ({ children }) => {
  return (
    <Flex direction="column" justify="space-between" width={1}>
      {children}
    </Flex>
  );
};

const GenericItemCardValuesGroup: React.FC = ({ children }) => {
  return (
    <Flex wrap="wrap" spacing={8}>
      {children}
    </Flex>
  );
};

const GenericItemCardLogo: React.FC<GenericItemCardLogoProps> = ({ src }) => {
  return <Img nativeWidth={20} nativeHeight={20} mr={5} alt="Logo" src={src} />;
};

const GenericItemCardOptions = React.forwardRef<HTMLButtonElement>(function GenericItemCardOptions(
  props,
  ref
) {
  return (
    <Box m={-4} position="absolute" top={0} right={0} transform="rotate(90deg)">
      <IconButton
        variant="ghost"
        variantColor="navyblue"
        icon="more"
        aria-label="Toggle Options"
        {...props}
        ref={ref}
      />
    </Box>
  );
});

const GenericItemCardValue: React.FC<GenericItemCardValueProps> = ({ label, value, id }) => {
  const cardId = id || slugify(`${label}${value}`);

  return (
    <Box as="dl" mt={4}>
      {label && (
        <Box
          as="dt"
          aria-labelledby={cardId}
          color="gray-300"
          fontSize="2x-small"
          mb="6px"
          fontWeight="medium"
        >
          {label}
        </Box>
      )}
      <Box
        as="dd"
        aria-labelledby={cardId}
        fontSize="medium"
        fontWeight="medium"
        opacity={value ? 1 : 0.3}
      >
        {value || 'Not Set'}
      </Box>
    </Box>
  );
};

const GenericItemCardLineBreak: React.FC = () => <Box flexBasis="100%" height={0} />;

GenericItemCard.Body = GenericItemCardBody;
GenericItemCard.Heading = GenericItemCardHeading;
GenericItemCard.Logo = GenericItemCardLogo;
GenericItemCard.Options = GenericItemCardOptions;
GenericItemCard.Value = GenericItemCardValue;
GenericItemCard.ValuesGroup = GenericItemCardValuesGroup;
GenericItemCard.LineBreak = GenericItemCardLineBreak;

export default GenericItemCard;
