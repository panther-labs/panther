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
import queryString from 'query-string';
import { queryStringOptions } from 'Hooks/useUrlParams';
import { fireClickAndMouseEvents, fireEvent, render, waitMs, within } from 'test-utils';
import { ListRulesSortFieldsEnum, SeverityEnum, SortDirEnum } from 'Generated/schema';
import ListRulesFilters from './index';

// Mock debounce so it just executes the callback instantly
jest.mock('lodash/debounce', () => jest.fn(fn => fn));

const parseParams = (search: string) => queryString.parse(search, queryStringOptions);

describe('ListRulesFilters', () => {
  it('renders', () => {
    const { container, getByText } = render(<ListRulesFilters />);
    expect(getByText('Create New Rule')).toBeInTheDocument();

    expect(container).toMatchSnapshot();
  });

  it('initializes correctly with url params', () => {
    const initialRoute = `?enabled=true&nameContains=AWS&page=1&sortBy=${ListRulesSortFieldsEnum.Severity}&sortDir=${SortDirEnum.Ascending}`;
    const { getByLabelText, getAllByLabelText } = render(<ListRulesFilters />, {
      initialRoute,
    });
    expect(getByLabelText('Filter Rules by text')).toHaveValue('AWS');
    expect(getAllByLabelText('Sort By')[0]).toHaveValue('Severity Ascending');
  });

  it('updates url params when sort by option changes', async () => {
    const { getByPlaceholderText, getByText, history } = render(<ListRulesFilters />);
    fireClickAndMouseEvents(getByPlaceholderText('Select a sort option'));
    fireClickAndMouseEvents(getByText('Severity Ascending'));
    await waitMs(1);
    const updatedParams = `?page=1&sortBy=${ListRulesSortFieldsEnum.Severity}&sortDir=${SortDirEnum.Ascending}`;
    expect(parseParams(history.location.search)).toEqual(parseParams(updatedParams));
  });

  it('updates url params when search input changes', async () => {
    const { getByPlaceholderText, history } = render(<ListRulesFilters />);
    fireEvent.change(getByPlaceholderText('Search for a rule...'), { target: { value: 'AWS' } });
    await waitMs(1);
    const updatedParams = '?nameContains=AWS&page=1';
    expect(parseParams(history.location.search)).toEqual(parseParams(updatedParams));
  });

  it('updates url params when multiple filters change', async () => {
    const { getByPlaceholderText, findByTestId, getByText, history } = render(<ListRulesFilters />);
    const searchInput = getByPlaceholderText('Search for a rule...');
    fireEvent.change(searchInput, { target: { value: 'AWS' } });
    fireClickAndMouseEvents(getByPlaceholderText('Select a sort option'));
    fireClickAndMouseEvents(getByText('Severity Ascending'));
    fireClickAndMouseEvents(getByText('Filters'));
    // Open the Dropdown
    const withinDropdown = within(await findByTestId('dropdown-rule-listing-filters'));

    // Modify all the filter values
    fireClickAndMouseEvents(withinDropdown.getAllByLabelText('Severities')[0]);
    fireEvent.click(withinDropdown.getByText('Info'));
    fireClickAndMouseEvents(withinDropdown.getAllByLabelText('Enabled')[0]);
    fireEvent.click(withinDropdown.getByText('Yes'));

    // Apply the new values of the dropdown filters
    fireClickAndMouseEvents(withinDropdown.getByText('Apply Filters'));

    await waitMs(1);

    const updatedParams = `?enabled=true&nameContains=AWS&page=1&severity[]=${SeverityEnum.Info}&sortBy=${ListRulesSortFieldsEnum.Severity}&sortDir=${SortDirEnum.Ascending}`;
    expect(parseParams(history.location.search)).toEqual(parseParams(updatedParams));
  });
});
