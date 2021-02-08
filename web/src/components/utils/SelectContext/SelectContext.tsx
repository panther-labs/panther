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

import React, { ReactNode } from 'react';

const identity = (x: any) => x;

export interface SelectContextValue<T> {
  selection: T[];
  selectItem: (item: T) => void;
  deselectItem: (item: T) => void;
  resetSelection: () => void;
  selectAll: (items: T[]) => void;
  checkIfSelected: (item: T) => boolean;
  toggleItem: (item: T) => void;
}

const SelectContext = React.createContext<SelectContextValue<any>>(undefined);

interface SelectProviderProps<T> {
  children: React.ReactNode;
  initialSelection?: T[];
  getItemKey?: (item: T) => string;
}

function SelectProvider<T>({
  initialSelection = [],
  getItemKey = identity,
  children,
}: SelectProviderProps<T>) {
  const [selection, setSelected] = React.useState<Array<T>>(initialSelection);

  /**
   * @public
   * Add an item to the selection
   *
   */
  const selectItem = React.useCallback(item => {
    return setSelected(existing => [...existing, item]);
  }, []);

  /**
   * @public
   * Deselects an item from the selection
   *
   */
  const deselectItem = React.useCallback(
    item => {
      return setSelected(existing => existing.filter(i => getItemKey(i) !== getItemKey(item)));
    },
    [getItemKey]
  );

  /**
   * @public
   * Reset selection to an empty array
   *
   */
  const resetSelection = React.useCallback(() => setSelected([]), []);

  const selectAll = React.useCallback((items: T[]) => {
    return setSelected(items);
  }, []);

  /**
   * @public
   * Simple function that checks whether an item is selected
   *
   */
  const checkIfSelected = React.useCallback(
    (item: T) => {
      return !!selection.find(i => getItemKey(i) === getItemKey(item));
    },
    [selection, getItemKey]
  );

  /**
   * @public
   * This function check whether an item is selected
   * and change its status to the opposite
   */
  const toggleItem = React.useCallback(
    (item: T) => {
      return checkIfSelected(item) ? deselectItem(item) : selectItem(item);
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
}

const MemoizedSelectProvider = React.memo(SelectProvider);

const withSelectContext = (Component: React.FC) => props => (
  <SelectProvider>
    <Component {...props} />
  </SelectProvider>
);

const useSelect = <T extends unknown = string>() =>
  React.useContext<SelectContextValue<T>>(SelectContext);

/** A shortcut for the consumer component */

const SelectConsumer = <T extends unknown = string>(
  props: React.ConsumerProps<SelectContextValue<T>>
) => {
  const Consumer = SelectContext.Consumer as React.Consumer<SelectContextValue<T>>;
  return <Consumer {...props} />;
};

export {
  SelectContext,
  SelectConsumer,
  MemoizedSelectProvider as SelectProvider,
  withSelectContext,
  useSelect,
};
