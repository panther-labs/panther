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
import { Dropdown, DropdownButton, DropdownItem, DropdownLink, DropdownMenu } from 'pouncejs';
import { DataModel } from 'Generated/schema';
import urls from 'Source/urls';
import { Link as RRLink } from 'react-router-dom';
import GenericItemCard from 'Components/GenericItemCard';
import { MODALS } from 'Components/utils/Modal';
import useModal from 'Hooks/useModal';

interface DataModelCardOptionsProps {
  dataModel: DataModel;
}

const DataModelCardOptions: React.FC<DataModelCardOptionsProps> = ({ dataModel }) => {
  const { showModal } = useModal();
  return (
    <Dropdown>
      <DropdownButton as={GenericItemCard.OptionsButton} />
      <DropdownMenu>
        <DropdownLink as={RRLink} to={urls.logAnalysis.dataModels.edit(dataModel.id)}>
          Edit
        </DropdownLink>
        <DropdownItem
          onSelect={() => {
            return showModal({
              modal: MODALS.DELETE_DATA_MODELS,
              props: { dataModels: [dataModel] },
            });
          }}
        >
          Delete
        </DropdownItem>
      </DropdownMenu>
    </Dropdown>
  );
};

export default React.memo(DataModelCardOptions);
