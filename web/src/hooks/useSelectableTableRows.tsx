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
import { Checkbox, TableProps } from 'pouncejs';

export interface UseSelectableTableRowsProps<T> {
  /**
   * A list of items that are going to be showcased by the Table. TableItem extends the basic JS
   * object, thus the shape of these items can by anything. Usually they keep the same
   * shape as the one that was returned from the API.
   */
  items: TableProps<T>['items'];

  /**
   * A list of column object that describe each column. More info on the shape of these objects
   * follows down below
   * */
  columns: TableProps<T>['columns'];
}

/**
 * A variation of the table where a first column is added in order to show the serial number of
 * each row
 * */
function useSelectableTableRows<ItemShape>({
  columns,
  items,
}: UseSelectableTableRowsProps<ItemShape>) {
  const [selectedItems, setSelectedItems] = React.useState<
    UseSelectableTableRowsProps<ItemShape>['items']
  >([]);

  /* eslint-disable react/display-name */
  const selectableColumns: TableProps<ItemShape>['columns'] = [
    {
      key: 'selection',
      flex: '0 1 auto',
      renderColumnHeader: () => (
        <Checkbox
          checked={selectedItems.length === items.length}
          onChange={checked => setSelectedItems(checked ? items : [])}
        />
      ),
      renderCell: item => (
        <Checkbox
          checked={selectedItems.includes(item)}
          onChange={(checked, e) => {
            e.stopPropagation();

            setSelectedItems(
              checked
                ? [...selectedItems, item]
                : selectedItems.filter(selectedItem => selectedItem !== item)
            );
          }}
        />
      ),
    },
    ...columns,
  ];
  /* eslint-enable react/display-name */

  return React.useMemo(() => ({ selectableColumns, selectedItems }), [
    items,
    columns,
    selectedItems,
  ]);
}

export default useSelectableTableRows;
