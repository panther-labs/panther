import React from 'react';
import { AbstractButton, Box, PseudoBox, Text } from 'pouncejs';

interface ColumnListItemProps {
  isSelected: boolean;
  isPristine: boolean;
  name: string;
  type: string;
  description?: string;
  onClick: (name: string) => void;
}

const ColumnListItem: React.FC<ColumnListItemProps> = ({
  isSelected,
  isPristine,
  name,
  type,
  description,
  onClick,
}) => {
  let columnNameColor;
  let columnTypeColor;
  if (isSelected || isPristine) {
    columnNameColor = 'grey500';
    columnTypeColor = 'grey200';
  } else {
    columnNameColor = 'grey200';
    columnTypeColor = 'grey100';
  }

  return (
    <Box as="li" key={name} mx={6}>
      <AbstractButton p={2} outline="none" textAlign="left" onClick={() => onClick(name)}>
        <PseudoBox
          color={columnNameColor}
          _hover={{
            color: 'grey500',
            // @ts-ignore
            i: { color: 'grey200' },
          }}
        >
          <Text size="medium" as="span">
            {name}
          </Text>
          <Text as="i" size="medium" fontWeight="bold" ml={1} title={type} color={columnTypeColor}>
            ({type})
          </Text>
          {isSelected && (
            <Text size="small" color="grey500" mt={2} as="p">
              {description || 'No description available'}
            </Text>
          )}
        </PseudoBox>
      </AbstractButton>
    </Box>
  );
};

export default React.memo(ColumnListItem);
