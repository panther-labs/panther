/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import React from 'react';
import { Dropdown, DropdownButton, DropdownMenu, DropdownItem } from 'pouncejs';
import GenericItemCard from 'Components/GenericItemCard';
import { MODALS } from 'Components/utils/Modal';
import useModal from 'Hooks/useModal';
import { ListCustomLogSchemas } from '../graphql/listCustomLogSchemas.generated';

interface CustomLogCardOptionsProps {
  customLog: ListCustomLogSchemas['listCustomLogs'][0];
}

const CustomLogCardOptions: React.FC<CustomLogCardOptionsProps> = ({ customLog }) => {
  const { showModal } = useModal();

  return (
    <Dropdown>
      <DropdownButton as={GenericItemCard.OptionsButton} />
      <DropdownMenu>
        <DropdownItem
          onSelect={() =>
            showModal({
              modal: MODALS.DELETE_CUSTOM_LOG,
              props: { customLog },
            })
          }
        >
          Delete
        </DropdownItem>
      </DropdownMenu>
    </Dropdown>
  );
};

export default React.memo(CustomLogCardOptions);
