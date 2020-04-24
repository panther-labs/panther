import { Box, Text, useTheme } from 'pouncejs';
import React from 'react';
import { css } from '@emotion/react';

interface TableListItemProps {
  name: string;
  onClick: (name: string) => void;
}

const TableListItem: React.FC<TableListItemProps> = ({ name, onClick }) => {
  const theme = useTheme();
  return (
    <Box
      as="li"
      key={name}
      borderTop="1px solid"
      borderColor="grey50"
      mx={6}
      borderRadius="medium"
      css={css`
        &:hover {
          background-color: ${theme.colors.grey50};

          &,
          & + * {
            border-color: ${theme.colors.grey50};
          }
        }
      `}
    >
      <Text
        px={2}
        py={3}
        width="100%"
        size="medium"
        color="grey500"
        as="button"
        cursor="pointer"
        outline="none"
        textAlign="left"
        onClick={() => onClick(name)}
        backgroundColor="transparent"
      >
        {name}
      </Text>
    </Box>
  );
};

export default React.memo(TableListItem);
