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
import { Box, Card, Flex, Icon, IconButton, Img, Text, TextProps, CardProps } from 'pouncejs';
import { slugify } from 'Helpers/utils';
import { Link as RRLink } from 'react-router-dom';

interface GenericItemCardLogoProps {
  src: string;
}

interface GenericItemCardValueProps {
  id?: string;
  label?: string;
  value: string | number | React.ReactElement;
}

interface GenericItemCardDate {
  date: string;
}
interface GenericItemCardLinkProps {
  to: string;
}

interface GenericItemCardComposition {
  Logo: React.FC<GenericItemCardLogoProps>;
  Header: React.FC;
  Heading: React.FC<TextProps>;
  Body: React.FC;
  Link: React.FC<GenericItemCardLinkProps>;
  OptionsButton: React.ForwardRefExoticComponent<React.RefAttributes<HTMLButtonElement>>;
  Value: React.FC<GenericItemCardValueProps>;
  ValuesGroup: React.FC;
  Date: React.FC<GenericItemCardDate>;
  LineBreak: React.FC;
}

const GenericItemCard: React.FC<CardProps> & GenericItemCardComposition = ({
  children,
  isHighlighted = false,
}) => {
  return (
    <Card as="section" variant="dark" overflow="hidden">
      <Box backgroundColor={isHighlighted ? 'navyblue-600' : 'transparent'} p={4}>
        <Flex position="relative" height="100%">
          {children}
        </Flex>
      </Box>
    </Card>
  );
};

const GenericItemCardHeader: React.FC = ({ children }) => {
  return (
    <Flex as="header" align="flex-start" mb={2}>
      {children}
    </Flex>
  );
};

const GenericItemCardHeading: React.FC<TextProps> = ({ children, ...rest }) => {
  return (
    <Text as="h4" fontWeight="medium" mr="auto" maxWidth="70%" wordBreak="break-word" {...rest}>
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

const GenericItemCardOptionsButton = React.forwardRef<HTMLButtonElement>(function OptionsButton(
  props,
  ref
) {
  return (
    <Box ml={2} mt={-1}>
      <IconButton
        variant="ghost"
        variantBorderStyle="circle"
        variantColor="navyblue"
        icon="more"
        size="small"
        aria-label="Toggle Options"
        {...props}
        ref={ref}
      />
    </Box>
  );
});

const GenericItemCardDate: React.FC<GenericItemCardDate> = ({ date, ...rest }) => {
  return (
    <Text fontSize="small" as="span" color="navyblue-100" {...rest}>
      {date}
    </Text>
  );
};

const GenericItemCardValue: React.FC<GenericItemCardValueProps> = ({ label, value, id }) => {
  const cardId = id || slugify(`${label}${value}`);

  return (
    <Flex direction="column" as="dl" mt={2}>
      {label && (
        <Box
          as="dt"
          aria-labelledby={cardId}
          color="gray-300"
          fontSize="2x-small"
          fontWeight="medium"
        >
          {label}
        </Box>
      )}
      <Box
        as="dd"
        display="inline-flex"
        flexGrow={1}
        aria-labelledby={cardId}
        fontSize="medium"
        fontWeight="medium"
        opacity={value ? 1 : 0.3}
        alignItems="center"
        minHeight={24}
      >
        {value || 'Not Set'}
      </Box>
    </Flex>
  );
};
const GenericItemCardLink: React.FC<GenericItemCardLinkProps> = ({ to, ...rest }) => {
  return (
    <RRLink to={to} {...rest}>
      <Flex
        justify="center"
        align="center"
        width={24}
        height={24}
        backgroundColor="navyblue-200"
        borderColor="navyblue-200"
        _hover={{ backgroundColor: 'blue-300', borderColor: 'blue-300' }}
        borderRadius="circle"
      >
        <Icon type="arrow-forward" size="x-small" />
      </Flex>
    </RRLink>
  );
};

const GenericItemCardLineBreak: React.FC = () => <Box flexBasis="100%" height={0} />;

GenericItemCard.Body = GenericItemCardBody;
GenericItemCard.Header = GenericItemCardHeader;
GenericItemCard.Link = React.memo(GenericItemCardLink);
GenericItemCard.Heading = GenericItemCardHeading;
GenericItemCard.Logo = GenericItemCardLogo;
GenericItemCard.OptionsButton = GenericItemCardOptionsButton;
GenericItemCard.Value = GenericItemCardValue;
GenericItemCard.ValuesGroup = GenericItemCardValuesGroup;
GenericItemCard.Date = GenericItemCardDate;
GenericItemCard.LineBreak = GenericItemCardLineBreak;

export default GenericItemCard;
