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

interface SelectCheckboxProps {
  id: string;
}

export interface SelectContextValue {
  selection: string[];
  selectItem: (id: string) => void;
  deselectItem: (id: string) => void;
  resetSelection: () => void;
  selectAll: (ids: string[]) => void;
}

const SelectContext = React.createContext<SelectContextValue>(undefined);

const SelectProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [selection, setSelected] = React.useState<Array<string>>([]);

  /**
   * @public
   * Add an item to the selection
   *
   */
  const selectItem = React.useCallback(id => setSelected([...selection, id]), [selection]);

  /**
   * @public
   * Deselects an item from the selection
   *
   */
  const deselectItem = React.useCallback(id => setSelected(selection.filter(i => i !== id)), [
    selection,
  ]);

  /**
   * @public
   * Reset selection to an empty array
   *
   */
  const resetSelection = React.useCallback(() => setSelected([]), []);

  // NOTE: Those ids could be passed on hook declaration
  const selectAll = React.useCallback((ids: string[]) => {
    setSelected(ids);
  }, []);

  const contextValue = React.useMemo(
    () => ({
      selection,
      selectAll,
      deselectItem,
      selectItem,
      resetSelection,
    }),
    [selection, resetSelection, selectAll, selectItem, deselectItem]
  );

  return <SelectContext.Provider value={contextValue}>{children}</SelectContext.Provider>;
};

const MemoizedSelectProvider = React.memo(SelectProvider);

const withSelectContext = (Component: React.FC) => props => (
  <SelectProvider>
    <Component {...props} />
  </SelectProvider>
);

const useSelect = () => React.useContext(SelectContext);

export { SelectContext, MemoizedSelectProvider as SelectProvider, withSelectContext, useSelect };

const SelectCheckboxComponent: React.FC<SelectCheckboxProps> = ({ id, ...rest }) => {
  const { selection, selectItem, deselectItem } = useSelect();
  const isSelected = selection && selection.find(i => i === id);
  return (
    <Checkbox
      checked={!!isSelected}
      onClick={() => (isSelected ? deselectItem(id) : selectItem(id))}
      {...rest}
    />
  );
};

export const SelectCheckbox = React.memo(SelectCheckboxComponent);
