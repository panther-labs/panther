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
import { Text } from 'pouncejs';
import { fireClickAndMouseEvents, render } from 'test-utils';
import { SelectProvider, useSelect } from 'Components/utils/SelectContext/SelectContext';
import { SelectCheckbox } from 'Components/utils/SelectContext/SelectCheckbox';
import { SelectAllCheckbox } from 'Components/utils/SelectContext/SelectAllCheckbox';

const TestingComponent: React.FC<{ items: string[] }> = ({ items }) => {
  const { checkIfSelected } = useSelect();
  return (
    <React.Fragment>
      {items.map(id => (
        <React.Fragment key={id}>
          <SelectCheckbox selectionId={id} />
          <Text>
            {id} is {checkIfSelected(id) ? 'selected' : 'unselected'}
          </Text>
        </React.Fragment>
      ))}
    </React.Fragment>
  );
};

describe('Select Context tests', () => {
  it('should select & unselect items', async () => {
    const items = ['a', 'b', 'c'];
    const [itemA, itemB] = items;

    const { getByText, getByAriaLabel } = render(
      <SelectProvider>
        <TestingComponent items={items} />
      </SelectProvider>
    );
    items.forEach(id => {
      expect(getByText(`${id} is unselected`));
    });

    const checkboxB = getByAriaLabel(`select ${itemB}`);
    await fireClickAndMouseEvents(checkboxB);
    expect(getByText(`${itemB} is selected`));
    expect(getByText(`${itemA} is unselected`));
    const uncheckboxB = getByAriaLabel(`unselect ${itemB}`);
    await fireClickAndMouseEvents(uncheckboxB);
    expect(getByText(`${itemB} is unselected`));
  });

  it('should select all & deselect all items', async () => {
    const items = ['a', 'b', 'c'];
    const { getByText, getByAriaLabel } = render(
      <SelectProvider>
        <SelectAllCheckbox selectionIds={items} />
        <TestingComponent items={items} />
      </SelectProvider>
    );
    items.forEach(id => {
      expect(getByText(`${id} is unselected`));
    });
    const selectAll = getByAriaLabel(`select all`);
    await fireClickAndMouseEvents(selectAll);
    items.forEach(id => {
      expect(getByText(`${id} is selected`));
    });
    const deselectAll = getByAriaLabel(`unselect all`);
    await fireClickAndMouseEvents(deselectAll);
    items.forEach(id => {
      expect(getByText(`${id} is unselected`));
    });
  });
});
