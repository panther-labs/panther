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
import { fireClickAndMouseEvents, fireEvent, render, within, waitFor } from 'test-utils';
import { ListDetectionsSortFieldsEnum, SortDirEnum } from 'Generated/schema';
import ListDetectionsFilters from './index';

// Mock debounce so it just executes the callback instantly
jest.mock('lodash/debounce', () => jest.fn(fn => fn));

const parseParams = (search: string) => queryString.parse(search, queryStringOptions);

describe('ListDetectionsFilters', () => {
  const filtersUrlParams = `?analysisTypes[]=RULE&complianceStatus=ERROR&enabled=true&hasRemediation=true&initialSet=true&nameContains=AWS&page=1&sortBy=${ListDetectionsSortFieldsEnum.Severity}&sortDir=${SortDirEnum.Ascending}`;

  it('renders', () => {
    const { container, getByAriaLabel } = render(<ListDetectionsFilters />);
    expect(getByAriaLabel('Create a new Detection')).toBeInTheDocument();

    expect(container).toMatchSnapshot();
  });

  it('initializes correctly from url params', () => {
    const { getByLabelText, getAllByLabelText, getByAriaLabel, getByTestId } = render(
      <ListDetectionsFilters />,
      {
        initialRoute: filtersUrlParams,
      }
    );
    expect(getByLabelText('Filter detections by text')).toHaveValue('AWS');
    expect(getAllByLabelText('Sort By')[0]).toHaveValue('Info to Critical');

    fireClickAndMouseEvents(getByAriaLabel('Detection Options'));

    const withinDropdown = within(getByTestId('dropdown-detections-listing-filters'));
    expect(withinDropdown.getAllByLabelText('State')[0]).toHaveValue('Enabled');
    expect(withinDropdown.getAllByLabelText('Policy Status')[0]).toHaveValue('Error');
    expect(withinDropdown.getAllByLabelText('Remediation Status')[0]).toHaveValue('Configured');
    expect(withinDropdown.getAllByLabelText('Created by')[0]).toHaveValue('Panther (system)');
    expect(withinDropdown.getByText('Rule')).toBeInTheDocument();
  });

  it('updates url params when filters change or get cleared', async () => {
    const {
      getAllByLabelText,
      getByText,
      history,
      getByLabelText,
      getByAriaLabel,
      getByTestId,
    } = render(<ListDetectionsFilters />);

    const dropdownTrigger = getByAriaLabel('Detection Options');

    fireEvent.change(getByLabelText('Filter detections by text'), { target: { value: 'AWS' } });

    fireClickAndMouseEvents(getAllByLabelText('Sort By')[0]);
    fireClickAndMouseEvents(getByText('Info to Critical'));

    fireClickAndMouseEvents(dropdownTrigger);

    // wait for debounce to kick in and update some stuff and then continue
    await waitFor(() => expect(history.location.search).toContain('nameContains'));

    const dropdown = getByTestId('dropdown-detections-listing-filters');
    let withinDropdown = within(dropdown);

    fireClickAndMouseEvents(withinDropdown.getAllByLabelText('State')[0]);
    fireClickAndMouseEvents(withinDropdown.getByText('Enabled'));

    fireClickAndMouseEvents(withinDropdown.getAllByLabelText('Policy Status')[0]);
    fireClickAndMouseEvents(withinDropdown.getByText('Error'));

    fireClickAndMouseEvents(withinDropdown.getAllByLabelText('Remediation Status')[0]);
    fireClickAndMouseEvents(withinDropdown.getByText('Configured'));

    fireClickAndMouseEvents(withinDropdown.getAllByLabelText('Created by')[0]);
    fireClickAndMouseEvents(withinDropdown.getByText('Panther (system)'));

    fireClickAndMouseEvents(withinDropdown.getAllByLabelText('Detection Types')[0]);
    fireClickAndMouseEvents(withinDropdown.getByText('Rule'));

    fireClickAndMouseEvents(withinDropdown.getByText('Apply Filters'));
    await waitFor(() =>
      expect(parseParams(history.location.search)).toEqual(parseParams(filtersUrlParams))
    );

    await waitFor(() => expect(dropdown).not.toBeInTheDocument());

    fireClickAndMouseEvents(dropdownTrigger);

    withinDropdown = within(getByTestId('dropdown-detections-listing-filters'));
    fireClickAndMouseEvents(withinDropdown.getByText('Clear Filters'));
    fireClickAndMouseEvents(withinDropdown.getByText('Apply Filters'));

    await waitFor(() =>
      expect(parseParams(history.location.search)).toEqual({
        nameContains: 'AWS',
        page: 1,
        sortBy: ListDetectionsSortFieldsEnum.Severity,
        sortDir: SortDirEnum.Ascending,
      })
    );
  });
});
