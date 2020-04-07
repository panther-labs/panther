import React from 'react';
import { Box, Flex, Text, useTheme } from 'pouncejs';
import { css } from '@emotion/react';

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
  const theme = useTheme();

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
    <Box is="li" key={name} mx={6}>
      <Text
        width="100%"
        p={2}
        size="medium"
        color={columnNameColor}
        is="button"
        cursor="pointer"
        outline="none"
        textAlign="left"
        onClick={() => onClick(name)}
        css={css`
          &:hover {
            color: ${theme.colors.grey500};

            span {
              color: ${theme.colors.grey200};
            }
          }
        `}
      >
        <Flex>
          {name}
          <Text
            is="span"
            fontStyle="italic"
            size="medium"
            fontWeight="bold"
            ml={1}
            title={type}
            color={columnTypeColor}
          >
            ({type})
          </Text>
        </Flex>
        {isSelected && (
          <Text size="small" color="grey500" mt={2} is="p">
            {description || 'No description available'}
          </Text>
        )}
      </Text>
    </Box>
  );
};

export default React.memo(ColumnListItem);
