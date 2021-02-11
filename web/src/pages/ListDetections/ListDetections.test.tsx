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
  buildPolicy,
  buildRule,
  fireClickAndMouseEvents,
  fireEvent,
  render,
  within,
} from 'test-utils';
import { queryStringOptions } from 'Hooks/useUrlParams';
import queryString from 'query-string';
import { EventEnum, SrcEnum, trackError, TrackErrorEnum, trackEvent } from 'Helpers/analytics';
import { GraphQLError } from 'graphql';
import { mockListAvailableLogTypes } from 'Source/graphql/queries';
import { mockDeleteDetections } from 'Components/modals/DeleteDetectionsModal';
import { DEFAULT_SMALL_PAGE_SIZE } from 'Source/constants';
import { mockListDetections } from './graphql/listDetections.generated';
import ListDetections from './ListDetections';

// Mock debounce so it just executes the callback instantly
jest.mock('lodash/debounce', () => jest.fn(fn => fn));
jest.mock('Helpers/analytics');

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

  it('allows you to select & delete multiple detections', async () => {
    const initialFiltersUrlParams = `?page=1&pageSize=${DEFAULT_SMALL_PAGE_SIZE}`;

    const mocks = [
      mockListDetections({
        variables: {
          input: {
            page: 1,
            pageSize: DEFAULT_SMALL_PAGE_SIZE,
          },
        },
        data: {
          detections: buildListDetectionsResponse({
            detections: [
              buildPolicy({ id: '1', displayName: 'First Rule' }),
              buildRule({ id: '2', displayName: 'Second Rule' }),
            ],
          }),
        },
      }),
      mockDeleteDetections({
        variables: {
          input: {
            detections: [{ id: '1' }, { id: '2' }],
          },
        },
        data: { deleteDetections: true },
      }),
    ];

    const { findByText, queryByText, getByText, getByAriaLabel, getAllByAriaLabel } = render(
      <ListDetections />,
      {
        mocks,
        initialRoute: initialFiltersUrlParams,
      }
    );

    // Wait for the first results to appear
    await findByText('First Rule');
    await findByText('Second Rule');

    // Click on all the checkboxes
    getAllByAriaLabel('select item').forEach(fireEvent.click);
    expect(getByText('2 Selected')).toBeInTheDocument();

    // Click on "unselect all" button
    fireEvent.click(getByAriaLabel('unselect all'));
    expect(queryByText('2 Selected')).not.toBeInTheDocument();

    // Select them all and attempt to delete them
    fireEvent.click(getByAriaLabel('select all'));
    fireEvent.click(getByText('Apply'));
    expect(getByText('Are you sure you want to delete 2 detections?')).toBeInTheDocument();

    fireEvent.click(getByText('Confirm'));

    expect(await findByText('Successfully deleted 2 detections')).toBeInTheDocument();
    expect(queryByText('First Rule')).not.toBeInTheDocument();
    expect(queryByText('Second Rule')).not.toBeInTheDocument();

    // Expect analytics to have been called
    expect(trackEvent).toHaveBeenCalledWith({
      event: EventEnum.DeletedDetection,
      src: SrcEnum.Detections,
    });
  });

  it('allows you to select & delete a single detection', async () => {
    const initialFiltersUrlParams = `?page=1&pageSize=${DEFAULT_SMALL_PAGE_SIZE}`;

    const mocks = [
      mockListDetections({
        variables: {
          input: {
            page: 1,
            pageSize: DEFAULT_SMALL_PAGE_SIZE,
          },
        },
        data: {
          detections: buildListDetectionsResponse({
            detections: [
              buildPolicy({ id: '1', displayName: 'First Rule' }),
              buildRule({ id: '2', displayName: 'Second Rule' }),
            ],
          }),
        },
      }),
      mockDeleteDetections({
        variables: {
          input: {
            detections: [{ id: '1' }],
          },
        },
        data: { deleteDetections: true },
      }),
    ];

    const { findByText, getByText, findAllByAriaLabel, queryByText } = render(<ListDetections />, {
      mocks,
      initialRoute: initialFiltersUrlParams,
    });

    // Click on one detection and attempt to delete it
    fireEvent.click((await findAllByAriaLabel('select item'))[0]);
    fireEvent.click(getByText('Apply'));
    fireEvent.click(getByText('Confirm'));

    expect(await findByText('Successfully deleted detection')).toBeInTheDocument();
    expect(queryByText('First Rule')).not.toBeInTheDocument();

    // Expect analytics to have been called
    expect(trackEvent).toHaveBeenCalledWith({
      event: EventEnum.DeletedDetection,
      src: SrcEnum.Detections,
    });
  });

  it('handles deletion failures', async () => {
    const initialFiltersUrlParams = `?page=1&pageSize=${DEFAULT_SMALL_PAGE_SIZE}`;

    const mocks = [
      mockListDetections({
        variables: {
          input: {
            page: 1,
            pageSize: DEFAULT_SMALL_PAGE_SIZE,
          },
        },
        data: {
          detections: buildListDetectionsResponse({
            detections: [
              buildPolicy({ id: '1', displayName: 'First Rule' }),
              buildRule({ id: '2', displayName: 'Second Rule' }),
            ],
          }),
        },
      }),
      mockDeleteDetections({
        variables: {
          input: {
            detections: [{ id: '1' }],
          },
        },
        data: null,
        errors: [new GraphQLError('Fake Error')],
      }),
    ];

    const { findByText, getByText, findAllByAriaLabel } = render(<ListDetections />, {
      mocks,
      initialRoute: initialFiltersUrlParams,
    });

    // Click on one detection and attempt to delete it
    fireEvent.click((await findAllByAriaLabel('select item'))[0]);
    fireEvent.click(getByText('Apply'));
    fireEvent.click(getByText('Confirm'));

    expect(await findByText('Failed to delete detection')).toBeInTheDocument();
    expect(getByText('Fake Error')).toBeInTheDocument();

    // Expect analytics to have been called
    expect(trackError).toHaveBeenCalledWith({
      event: TrackErrorEnum.FailedToDeleteDetection,
      src: SrcEnum.Detections,
    });
  });
});
