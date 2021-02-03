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
import {
  buildListDetectionsResponse,
  buildRule,
  fireClickAndMouseEvents,
  fireEvent,
  render,
  within,
} from 'test-utils';
import { queryStringOptions } from 'Hooks/useUrlParams';
import queryString from 'query-string';
import { mockListAvailableLogTypes } from 'Source/graphql/queries';
import { DEFAULT_SMALL_PAGE_SIZE } from 'Source/constants';
import { mockListDetections } from './graphql/listDetections.generated';
import ListDetections from './ListDetections';

// Mock debounce so it just executes the callback instantly
jest.mock('lodash/debounce', () => jest.fn(fn => fn));

const parseParams = (search: string) => queryString.parse(search, queryStringOptions);

describe('ListDetections', () => {
  it('shows a placeholder while loading', () => {
    const { getAllByAriaLabel } = render(<ListDetections />);

    const loadingBlocks = getAllByAriaLabel('Loading interface...');
    expect(loadingBlocks.length).toBeGreaterThan(1);
  });

  it('changes the results depending on the filters applied', async () => {
    const mockedlogType = 'AWS.ALB';

    const initialFiltersUrlParams = `?analysisTypes[]=RULE&page=1&pageSize=${DEFAULT_SMALL_PAGE_SIZE}`;
    const updatedFiltersUrlParams = `${initialFiltersUrlParams}&logTypes[]=${mockedlogType}`;

    const parsedInitialParams = parseParams(initialFiltersUrlParams);
    const parsedUpdatedParams = parseParams(updatedFiltersUrlParams);

    const mocks = [
      mockListAvailableLogTypes({
        data: {
          listAvailableLogTypes: {
            logTypes: [mockedlogType],
          },
        },
      }),
      mockListDetections({
        variables: {
          input: parsedInitialParams,
        },
        data: {
          detections: buildListDetectionsResponse({
            detections: [buildRule({ displayName: 'Initial Rule' })],
          }),
        },
      }),
      mockListDetections({
        variables: {
          input: parsedUpdatedParams,
        },
        data: {
          detections: buildListDetectionsResponse({
            detections: [buildRule({ displayName: 'Filtered Rule' })],
          }),
        },
      }),
    ];

    const { findByText, getByText, getByTestId } = render(<ListDetections />, {
      initialRoute: initialFiltersUrlParams,
      mocks,
    });

    // Wait for the first results to appear
    await findByText('Initial Rule');

    // Open the Dropdown
    fireClickAndMouseEvents(getByText('Filters (1)'));
    const withinDropdown = within(getByTestId('dropdown-detections-listing-filters'));

    // Expect to see the existing filter
    expect(withinDropdown.getByText('Rule')).toBeInTheDocument();

    // Modify another filter
    const logTypesField = withinDropdown.getAllByLabelText('Log Types')[0];
    fireEvent.change(logTypesField, { target: { value: mockedlogType } });
    fireEvent.click(await findByText(mockedlogType));
    fireEvent.click(withinDropdown.getByText('Apply Filters'));

    // Expect detection items to update & filter count to write "2"
    expect(await findByText('Filtered Rule')).toBeInTheDocument();
    expect(getByText('Filters (2)')).toBeInTheDocument();
  });
});
