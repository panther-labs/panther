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
import { Dropdown, DropdownButton, DropdownMenu, DropdownItem, DropdownLink } from 'pouncejs';
import GenericItemCard from 'Components/GenericItemCard';
import { MODALS } from 'Components/utils/Modal';
import useModal from 'Hooks/useModal';
import urls from 'Source/urls';
import { Link as RRLink } from 'react-router-dom';
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
        <DropdownLink as={RRLink} to={urls.logAnalysis.customLogs.edit(customLog.logType)}>
          Edit
        </DropdownLink>
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
