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
import { SelectProvider, useSelect, SelectCheckbox, SelectAllCheckbox } from './index';

const items = [{ id: 'a' }, { id: 'b' }];
type Item = typeof items[0];

const TestingComponent: React.FC<{ items: Item[] }> = ({ items: itms }) => {
  const { checkIfSelected } = useSelect<Item>();
  return (
    <React.Fragment>
      {itms.map(item => (
        <React.Fragment key={item.id}>
          <SelectCheckbox selectionItem={item} />
          <Text>
            {item.id} is {checkIfSelected(item) ? 'selected' : 'unselected'}
          </Text>
        </React.Fragment>
      ))}
    </React.Fragment>
  );
};

describe('Select Context tests', () => {
  it('should select & unselect items', async () => {
    const { getByText, getAllByAriaLabel } = render(
      <SelectProvider>
        <TestingComponent items={items} />
      </SelectProvider>
    );
    const [checkboxA, checkboxB] = getAllByAriaLabel(`select item`);

    items.forEach(item => {
      expect(getByText(`${item.id} is unselected`));
    });

    await fireClickAndMouseEvents(checkboxA);
    expect(getByText(`${items[0].id} is selected`));
    expect(getByText(`${items[1].id} is unselected`));

    await fireClickAndMouseEvents(checkboxB);
    expect(getByText(`${items[0].id} is selected`));
    expect(getByText(`${items[1].id} is selected`));
  });

  it('should select all & deselect all items', async () => {
    const { getByText, getByAriaLabel } = render(
      <SelectProvider>
        <SelectAllCheckbox selectionItems={items} />
        <TestingComponent items={items} />
      </SelectProvider>
    );

    items.forEach(item => {
      expect(getByText(`${item.id} is unselected`));
    });

    await fireClickAndMouseEvents(getByAriaLabel(`select all`));
    items.forEach(item => {
      expect(getByText(`${item.id} is selected`));
    });

    await fireClickAndMouseEvents(getByAriaLabel('unselect all'));
    items.forEach(item => {
      expect(getByText(`${item.id} is unselected`));
    });
  });
});
