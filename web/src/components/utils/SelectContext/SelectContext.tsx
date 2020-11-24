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

export interface SelectContextValue {
  selection: string[];
  selectItem: (id: string) => void;
  deselectItem: (id: string) => void;
  resetSelection: () => void;
  selectAll: (ids: string[]) => void;
  checkIfSelected: (id) => boolean;
  toggleItem: (id) => void;
}

const SelectContext = React.createContext<SelectContextValue>(undefined);

interface SelectProviderProps {
  children: React.ReactNode;
  initialSelection?: string[];
}

const SelectProvider: React.FC<SelectProviderProps> = ({ initialSelection = [], children }) => {
  const [selection, setSelected] = React.useState<Array<string>>(initialSelection);

  /**
   * @public
   * Add an item to the selection
   *
   */
  const selectItem = React.useCallback(
    id => {
      return setSelected([...selection, id]);
    },
    [selection]
  );

  /**
   * @public
   * Deselects an item from the selection
   *
   */
  const deselectItem = React.useCallback(
    id => {
      return setSelected(selection.filter(i => i !== id));
    },
    [selection]
  );

  /**
   * @public
   * Reset selection to an empty array
   *
   */
  const resetSelection = React.useCallback(() => setSelected([]), []);

  const selectAll = React.useCallback((ids: string[]) => {
    return setSelected(ids);
  }, []);

  /**
   * @public
   * Simple function that checks whether an item is selected
   *
   */
  const checkIfSelected = React.useCallback(
    id => {
      return !!selection.find(i => i === id);
    },
    [selection]
  );

  /**
   * @public
   * This function check whether an item is selected
   * and change its status to the opposite
   */
  const toggleItem = React.useCallback(
    id => {
      const isSelected = checkIfSelected(id);
      return isSelected ? deselectItem(id) : selectItem(id);
    },
    [checkIfSelected, deselectItem, selectItem]
  );

  const contextValue = React.useMemo(
    () => ({
      selection,
      selectAll,
      deselectItem,
      selectItem,
      resetSelection,
      checkIfSelected,
      toggleItem,
    }),
    [selection, resetSelection, selectAll, selectItem, deselectItem, checkIfSelected, toggleItem]
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
/** A shortcut for the consumer component */
const SelectConsumer = SelectContext.Consumer;

export {
  SelectContext,
  SelectConsumer,
  MemoizedSelectProvider as SelectProvider,
  withSelectContext,
  useSelect,
};
