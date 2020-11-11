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
import { Checkbox } from 'pouncejs';
import { useSelect } from './SelectContext';

interface SelectCheckboxProps {
  selectionId: string;
}

const SelectCheckboxComponent: React.FC<SelectCheckboxProps> = ({ selectionId, ...rest }) => {
  const { checkIfSelected, toggleItem } = useSelect();
  const isSelected = checkIfSelected(selectionId);
  return (
    <Checkbox
      checked={isSelected}
      aria-label={isSelected ? `unselect ${selectionId}` : `select ${selectionId}`}
      onChange={() => toggleItem(selectionId)}
      {...rest}
    />
  );
};

export const SelectCheckbox = React.memo(SelectCheckboxComponent);
