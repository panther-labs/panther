import { AbstractButton, PseudoBox, Text } from 'pouncejs';
import React from 'react';

interface TableListItemProps {
  name: string;
  onClick: (name: string) => void;
}

const TableListItem: React.FC<TableListItemProps> = ({ name, onClick }) => {
  return (
    <PseudoBox
      as="li"
      key={name}
      borderTop="1px solid"
      borderColor="grey50"
      mx={6}
      _hover={{
        borderRadius: 'medium',
        backgroundColor: 'grey50',
      }}
    >
      <AbstractButton
        px={2}
        py={3}
        width="100%"
        outline="none"
        textAlign="left"
        onClick={() => onClick(name)}
        backgroundColor="transparent"
      >
        <Text size="medium" color="grey500">
          {name}
        </Text>
      </AbstractButton>
    </PseudoBox>
  );
};

export default React.memo(TableListItem);
