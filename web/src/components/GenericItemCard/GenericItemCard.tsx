import React from 'react';
import { Box, Card, Flex, IconButton, Img, Text, TextProps } from 'pouncejs';
import { slugify } from 'Helpers/utils';

interface GenericItemCardLogoProps {
  src: string;
}

interface GenericItemCardValueProps {
  label: string;
  value: string | React.ReactElement;
}

interface GenericItemCardComposition {
  Logo: React.FC<GenericItemCardLogoProps>;
  Heading: React.FC<TextProps>;
  Body: React.FC;
  Options: React.ForwardRefExoticComponent<React.RefAttributes<HTMLButtonElement>>;
  Value: React.FC<GenericItemCardValueProps>;
  ValuesGroup: React.FC;
}

const GenericItemCard: React.FC & GenericItemCardComposition = ({ children }) => {
  return (
    <Card as="section" variant="dark" p={5}>
      <Flex position="relative" height="100%">
        {children}
      </Flex>
    </Card>
  );
};

const GenericItemCardHeading: React.FC<TextProps> = ({ children, ...rest }) => {
  return (
    <Text fontWeight="medium" as="h4" {...rest}>
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

const GenericItemCardValue: React.FC<GenericItemCardValueProps> = ({ label, value }) => {
  const id = slugify(`${label}${value}`);

  return (
    <Box as="dl" mt={4}>
      <Box as="dt" aria-labelledby={id} color="gray-300" fontSize="2x-small" mb="1px">
        {label}
      </Box>
      <Box as="dd" aria-labelledby={id} fontSize="medium">
        {value}
      </Box>
    </Box>
  );
};

GenericItemCard.Body = GenericItemCardBody;
GenericItemCard.Heading = GenericItemCardHeading;
GenericItemCard.Logo = GenericItemCardLogo;
GenericItemCard.Options = GenericItemCardOptions;
GenericItemCard.Value = GenericItemCardValue;
GenericItemCard.ValuesGroup = GenericItemCardValuesGroup;

export default GenericItemCard;
