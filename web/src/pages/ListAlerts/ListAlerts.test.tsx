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
  buildAlertSummary,
  buildListAlertsResponse,
  fireClickAndMouseEvents,
  fireEvent,
  render,
  waitMs,
  within,
} from 'test-utils';
import {
  AlertStatusesEnum,
  ListAlertsSortFieldsEnum,
  SeverityEnum,
  SortDirEnum,
} from 'Generated/schema';
import { queryStringOptions } from 'Hooks/useUrlParams';
import MockDate from 'mockdate';
import queryString from 'query-string';
import { mockListAvailableLogTypes, mockUpdateAlertStatus } from 'Source/graphql/queries';
import { DEFAULT_LARGE_PAGE_SIZE } from 'Source/constants';
import { mockListAlerts } from './graphql/listAlerts.generated';
import ListAlerts from './ListAlerts';

// Mock debounce so it just executes the callback instantly
jest.mock('lodash/debounce', () => jest.fn(fn => fn));

const parseParams = (search: string) => queryString.parse(search, queryStringOptions);

describe('ListAlerts', () => {
  beforeAll(() => {
    // https://github.com/boblauer/MockDate#example
    // Forces a fixed resolution on `Date.now()`. Used for the DateRangePicker
    MockDate.set('1/30/2000');

    window.IntersectionObserver = jest.fn().mockReturnValue({
      observe: () => null,
      unobserve: () => null,
      disconnect: () => null,
    });
  });

  afterAll(() => {
    MockDate.reset();
  });

  it('shows a placeholder while loading', () => {
    const { getAllByAriaLabel } = render(<ListAlerts />);

    const loadingBlocks = getAllByAriaLabel('Loading interface...');
    expect(loadingBlocks.length).toBeGreaterThan(1);
  });

  it('can single select and update 2 alert status', async () => {
    const mockedlogType = 'AWS.ALB';

    // Populate Alerts
    const alertSummaries = [
      buildAlertSummary({ title: 'Test Alert 1', alertId: 'a' }),
      buildAlertSummary({ title: 'Test Alert 2', alertId: 'b' }),
      buildAlertSummary({ title: 'Test Alert 3', alertId: 'c' }),
    ];

    const mocks = [
      mockListAvailableLogTypes({
        data: {
          listAvailableLogTypes: {
            logTypes: [mockedlogType],
          },
        },
      }),
      mockListAlerts({
        variables: {
          input: {
            pageSize: DEFAULT_LARGE_PAGE_SIZE,
          },
        },
        data: {
          alerts: buildListAlertsResponse({
            alertSummaries,
          }),
        },
      }),
      mockUpdateAlertStatus({
        variables: {
          input: {
            // Set API call, so that it will change status for 2 alerts to Closed
            alertIds: [alertSummaries[1].alertId, alertSummaries[2].alertId],
            status: AlertStatusesEnum.Closed,
          },
        },
        data: {
          updateAlertStatus: [
            // Expected Response
            { ...alertSummaries[1], status: AlertStatusesEnum.Closed },
            { ...alertSummaries[2], status: AlertStatusesEnum.Closed },
          ],
        },
      }),
    ];

    const {
      getAllByLabelText,
      getByText,
      findByAriaLabel,
      getByAriaLabel,
      findAllByText,
      queryByAriaLabel,
      queryAllByText,
    } = render(<ListAlerts />, {
      mocks,
    });

    // Check that select all checkbox is present
    expect(await findByAriaLabel('select all')).toBeInTheDocument();
    // Check Alerts and checkboxs are rendered
    alertSummaries.forEach(alertSummary => {
      expect(getByText(alertSummary.title)).toBeInTheDocument();
    });
    alertSummaries.forEach(alertSummary => {
      expect(getByAriaLabel(`select ${alertSummary.alertId}`)).toBeInTheDocument();
    });

    // Single select all of 3 Alerts
    const checkboxForAlert1 = getByAriaLabel(`select ${alertSummaries[0].alertId}`);
    fireClickAndMouseEvents(checkboxForAlert1);
    expect(getByText('1 Selected')).toBeInTheDocument();
    const checkboxForAlert2 = getByAriaLabel(`select ${alertSummaries[1].alertId}`);
    fireClickAndMouseEvents(checkboxForAlert2);
    expect(getByText('2 Selected')).toBeInTheDocument();
    const checkboxForAlert3 = getByAriaLabel(`select ${alertSummaries[2].alertId}`);
    fireClickAndMouseEvents(checkboxForAlert3);
    expect(getByText('3 Selected')).toBeInTheDocument();

    // Deselect first alert
    const checkedCheckboxForAlert1 = getByAriaLabel(`unselect ${alertSummaries[0].alertId}`);
    fireClickAndMouseEvents(checkedCheckboxForAlert1);
    expect(getByText('2 Selected')).toBeInTheDocument();

    // Expect status field to have Resolved as default
    const statusField = getAllByLabelText('Status')[0];
    expect(statusField).toHaveValue('Resolved');

    // Change its value to Invalid (Closed)
    fireClickAndMouseEvents(statusField);
    fireClickAndMouseEvents(getByText('Invalid'));
    expect(statusField).toHaveValue('Invalid');
    expect(await queryAllByText('INVALID')).toHaveLength(0);
    fireClickAndMouseEvents(getByText('Apply'));

    // Find the alerts with the updated status
    expect(await findAllByText('INVALID')).toHaveLength(2);
    // And expect that the selection has been reset
    expect(await queryByAriaLabel(`unselect ${alertSummaries[1].alertId}`)).not.toBeInTheDocument();
    expect(await queryByAriaLabel(`unselect ${alertSummaries[2].alertId}`)).not.toBeInTheDocument();
  });

  it('can select all alerts and update their status', async () => {
    const mockedlogType = 'AWS.ALB';

    // Populate Alerts
    const alertSummaries = [
      buildAlertSummary({ title: 'Test Alert 1', alertId: 'a' }),
      buildAlertSummary({ title: 'Test Alert 2', alertId: 'b' }),
      buildAlertSummary({ title: 'Test Alert 3', alertId: 'c' }),
    ];

    const mocks = [
      mockListAvailableLogTypes({
        data: {
          listAvailableLogTypes: {
            logTypes: [mockedlogType],
          },
        },
      }),
      mockListAlerts({
        variables: {
          input: {
            pageSize: DEFAULT_LARGE_PAGE_SIZE,
          },
        },
        data: {
          alerts: buildListAlertsResponse({
            alertSummaries,
          }),
        },
      }),
      mockUpdateAlertStatus({
        variables: {
          input: {
            // Set API call, so that it will change status for Alerts to Open
            alertIds: alertSummaries.map(a => a.alertId),
            status: AlertStatusesEnum.Open,
          },
        },
        data: {
          updateAlertStatus: alertSummaries.map(a => ({
            ...a,
            status: AlertStatusesEnum.Open,
          })),
        },
      }),
    ];

    const {
      getAllByLabelText,
      getByText,
      findByAriaLabel,
      getByAriaLabel,
      findAllByText,
      queryByAriaLabel,
    } = render(<ListAlerts />, {
      mocks,
    });

    // Check that select all checkbox is present
    const selectAllCheckbox = await findByAriaLabel('select all');
    expect(selectAllCheckbox).toBeInTheDocument();
    // Check Alerts and checkboxes are rendered
    alertSummaries.forEach(alertSummary => {
      expect(getByText(alertSummary.title)).toBeInTheDocument();
    });
    alertSummaries.forEach(alertSummary => {
      expect(getByAriaLabel(`select ${alertSummary.alertId}`)).toBeInTheDocument();
    });

    fireClickAndMouseEvents(selectAllCheckbox);
    expect(getByText('3 Selected')).toBeInTheDocument();

    // Expect status field to have Resolved as default
    const statusField = getAllByLabelText('Status')[0];
    expect(statusField).toHaveValue('Resolved');

    // Change its value to Triaged
    fireClickAndMouseEvents(statusField);
    fireClickAndMouseEvents(getByText('Open'));
    expect(statusField).toHaveValue('Open');
    fireClickAndMouseEvents(getByText('Apply'));

    // Find the alerts with the updated status
    expect(await findAllByText('OPEN')).toHaveLength(alertSummaries.length);
    // And expect that the selection has been reset
    alertSummaries.forEach(alertSummary => {
      expect(queryByAriaLabel(`unselect ${alertSummary.alertId}`)).not.toBeInTheDocument();
    });
  });

  it('can correctly boot from URL params', async () => {
    const mockedlogType = 'AWS.ALB';
    const initialParams =
      `?createdAtAfter=2020-11-05T19%3A33%3A55Z` +
      `&createdAtBefore=2020-12-17T19%3A33%3A55Z` +
      `&eventCountMax=5` +
      `&eventCountMin=2` +
      `&logTypes[]=${mockedlogType}` +
      `&nameContains=test` +
      `&severity[]=${SeverityEnum.Info}&severity[]=${SeverityEnum.Medium}` +
      `&sortBy=${ListAlertsSortFieldsEnum.CreatedAt}&sortDir=${SortDirEnum.Descending}` +
      `&status[]=${AlertStatusesEnum.Open}&status[]=${AlertStatusesEnum.Triaged}` +
      `&pageSize=${DEFAULT_LARGE_PAGE_SIZE}`;

    const parsedInitialParams = parseParams(initialParams);
    const mocks = [
      mockListAvailableLogTypes({
        data: {
          listAvailableLogTypes: {
            logTypes: [mockedlogType],
          },
        },
      }),
      mockListAlerts({
        variables: {
          input: parsedInitialParams,
        },
        data: {
          alerts: buildListAlertsResponse({
            alertSummaries: [buildAlertSummary({ title: 'Test Alert' })],
          }),
        },
      }),
    ];

    const {
      findByText,
      getByLabelText,
      getAllByLabelText,
      getByText,
      findByTestId,
      findAllByLabelText,
    } = render(<ListAlerts />, {
      initialRoute: `/${initialParams}`,
      mocks,
    });

    // Await for API requests to resolve
    await findByText('Test Alert');
    await findAllByLabelText('Log Type');

    // Verify filter values outside of Dropdown
    expect(getByLabelText('Filter Alerts by text')).toHaveValue('test');
    expect(getByLabelText('Date Start')).toHaveValue('11/05/2020 19:33');
    expect(getByLabelText('Date End')).toHaveValue('12/17/2020 19:33');
    expect(getAllByLabelText('Sort By')[0]).toHaveValue('Most Recent');
    expect(getAllByLabelText('Log Type')[0]).toHaveValue(mockedlogType);

    // Verify filter value inside the Dropdown
    fireClickAndMouseEvents(getByText('Filters (4)'));
    const withinDropdown = within(await findByTestId('dropdown-alert-listing-filters'));
    expect(withinDropdown.getByText('Open')).toBeInTheDocument();
    expect(withinDropdown.getByText('Triaged')).toBeInTheDocument();
    expect(withinDropdown.getByText('Info')).toBeInTheDocument();
    expect(withinDropdown.getByText('Medium')).toBeInTheDocument();
    expect(withinDropdown.getByLabelText('Min Events')).toHaveValue(2);
    expect(withinDropdown.getByLabelText('Max Events')).toHaveValue(5);
  });

  it('correctly applies & resets dropdown filters', async () => {
    const mockedlogType = 'AWS.ALB';
    const initialParams =
      `?createdAtAfter=2020-11-05T19%3A33%3A55Z` +
      `&createdAtBefore=2020-12-17T19%3A33%3A55Z` +
      `&nameContains=test` +
      `&sortBy=${ListAlertsSortFieldsEnum.CreatedAt}&sortDir=${SortDirEnum.Descending}` +
      `&logTypes[]=${mockedlogType}` +
      `&pageSize=${DEFAULT_LARGE_PAGE_SIZE}`;

    const parsedInitialParams = parseParams(initialParams);

    const mocks = [
      mockListAvailableLogTypes({
        data: {
          listAvailableLogTypes: {
            logTypes: [mockedlogType],
          },
        },
      }),
      mockListAlerts({
        variables: {
          input: parsedInitialParams,
        },
        data: {
          alerts: buildListAlertsResponse({
            alertSummaries: [buildAlertSummary({ title: 'Initial Alert' })],
          }),
        },
      }),
      mockListAlerts({
        variables: {
          input: {
            ...parsedInitialParams,
            eventCountMin: 2,
            eventCountMax: 5,
            severity: [SeverityEnum.Info, SeverityEnum.Medium],
            status: [AlertStatusesEnum.Open, AlertStatusesEnum.Triaged],
          },
        },
        data: {
          alerts: buildListAlertsResponse({
            alertSummaries: [buildAlertSummary({ title: 'Filtered Alert' })],
          }),
        },
      }),
      mockListAlerts({
        variables: {
          input: parsedInitialParams,
        },
        data: {
          alerts: buildListAlertsResponse({
            alertSummaries: [buildAlertSummary({ title: 'Initial Alert' })],
          }),
        },
      }),
    ];

    const {
      findByText,
      getByLabelText,
      getAllByLabelText,
      getByText,
      findByTestId,
      findAllByLabelText,
      history,
    } = render(<ListAlerts />, {
      initialRoute: `/${initialParams}`,
      mocks,
    });

    // Wait for all API requests to resolve
    await findByText('Initial Alert');
    await findAllByLabelText('Log Type');

    // Open the Dropdown
    fireClickAndMouseEvents(getByText('Filters'));
    let withinDropdown = within(await findByTestId('dropdown-alert-listing-filters'));

    // Modify all the filter values
    fireClickAndMouseEvents(withinDropdown.getAllByLabelText('Status')[0]);
    fireEvent.click(withinDropdown.getByText('Open'));
    fireEvent.click(withinDropdown.getByText('Triaged'));
    fireClickAndMouseEvents(withinDropdown.getAllByLabelText('Severity')[0]);
    fireEvent.click(withinDropdown.getByText('Info'));
    fireEvent.click(withinDropdown.getByText('Medium'));
    fireEvent.change(withinDropdown.getByLabelText('Min Events'), { target: { value: 2 } });
    fireEvent.change(withinDropdown.getByLabelText('Max Events'), { target: { value: 5 } });

    // Expect nothing to have changed until "Apply is pressed"
    expect(parseParams(history.location.search)).toEqual(parseParams(initialParams));

    // Apply the new values of the dropdown filters
    fireEvent.click(withinDropdown.getByText('Apply Filters'));

    // Wait for side-effects to apply
    await waitMs(1);

    // Expect URL to have changed to mirror the filter updates
    const updatedParams =
      `${initialParams}` +
      `&eventCountMax=5` +
      `&eventCountMin=2` +
      `&severity[]=${SeverityEnum.Info}&severity[]=${SeverityEnum.Medium}` +
      `&status[]=${AlertStatusesEnum.Open}&status[]=${AlertStatusesEnum.Triaged}`;
    expect(parseParams(history.location.search)).toEqual(parseParams(updatedParams));

    // Await for the new API request to resolve
    await findByText('Filtered Alert');

    // Expect the rest of the filters to be intact (to not have changed in any way)
    expect(getByLabelText('Filter Alerts by text')).toHaveValue('test');
    expect(getByLabelText('Date Start')).toHaveValue('11/05/2020 19:33');
    expect(getByLabelText('Date End')).toHaveValue('12/17/2020 19:33');
    expect(getAllByLabelText('Sort By')[0]).toHaveValue('Most Recent');
    expect(getAllByLabelText('Log Type')[0]).toHaveValue(mockedlogType);

    // Open the Dropdown (again)
    fireClickAndMouseEvents(getByText('Filters (4)'));
    withinDropdown = within(await findByTestId('dropdown-alert-listing-filters'));

    // Clear all the filter values
    fireEvent.click(withinDropdown.getByText('Clear Filters'));

    // Verify that they are cleared
    expect(withinDropdown.queryByText('Open')).not.toBeInTheDocument();
    expect(withinDropdown.queryByText('Triaged')).not.toBeInTheDocument();
    expect(withinDropdown.queryByText('Info')).not.toBeInTheDocument();
    expect(withinDropdown.queryByText('Medium')).not.toBeInTheDocument();
    expect(withinDropdown.getByLabelText('Min Events')).toHaveValue(null);
    expect(withinDropdown.getByLabelText('Max Events')).toHaveValue(null);

    // Expect the URL to not have changed until "Apply Filters" is clicked
    expect(parseParams(history.location.search)).toEqual(parseParams(updatedParams));

    // Apply the changes from the "Clear Filters" button
    fireEvent.click(withinDropdown.getByText('Apply Filters'));

    // Wait for side-effects to apply
    await waitMs(1);

    // Expect the URL to reset to its original values
    expect(parseParams(history.location.search)).toEqual(parseParams(initialParams));

    // Expect the rest of the filters to STILL be intact (to not have changed in any way)
    expect(getByLabelText('Filter Alerts by text')).toHaveValue('test');
    expect(getByLabelText('Date Start')).toHaveValue('11/05/2020 19:33');
    expect(getByLabelText('Date End')).toHaveValue('12/17/2020 19:33');
    expect(getAllByLabelText('Sort By')[0]).toHaveValue('Most Recent');
    expect(getAllByLabelText('Log Type')[0]).toHaveValue(mockedlogType);
  });

  it('correctly updates filters & sorts on every change outside of the dropdown', async () => {
    const mockedlogType = 'AWS.ALB';
    const initialParams =
      `?severity[]=${SeverityEnum.Info}&severity[]=${SeverityEnum.Medium}` +
      `&status[]=${AlertStatusesEnum.Open}&status[]=${AlertStatusesEnum.Triaged}` +
      `&eventCountMin=2` +
      `&eventCountMax=5` +
      `&pageSize=${DEFAULT_LARGE_PAGE_SIZE}`;

    const parsedInitialParams = parseParams(initialParams);
    const mocks = [
      mockListAvailableLogTypes({
        data: {
          listAvailableLogTypes: {
            logTypes: [mockedlogType],
          },
        },
      }),
      mockListAlerts({
        variables: {
          input: parsedInitialParams,
        },
        data: {
          alerts: buildListAlertsResponse({
            alertSummaries: [buildAlertSummary({ title: 'Initial Alert' })],
          }),
        },
      }),
      mockListAlerts({
        variables: {
          input: { ...parsedInitialParams, nameContains: 'test' },
        },
        data: {
          alerts: buildListAlertsResponse({
            alertSummaries: [buildAlertSummary({ title: 'Text Filtered Alert' })],
          }),
        },
      }),
      mockListAlerts({
        variables: {
          input: {
            ...parsedInitialParams,
            nameContains: 'test',
            sortBy: ListAlertsSortFieldsEnum.CreatedAt,
            sortDir: SortDirEnum.Descending,
          },
        },
        data: {
          alerts: buildListAlertsResponse({
            alertSummaries: [buildAlertSummary({ title: 'Sorted Alert' })],
          }),
        },
      }),
      mockListAlerts({
        variables: {
          input: {
            ...parsedInitialParams,
            nameContains: 'test',
            sortBy: ListAlertsSortFieldsEnum.CreatedAt,
            sortDir: SortDirEnum.Descending,
            logTypes: [mockedlogType],
          },
        },
        data: {
          alerts: buildListAlertsResponse({
            alertSummaries: [buildAlertSummary({ title: 'Log Filtered Alert' })],
          }),
        },
      }),
      mockListAlerts({
        variables: {
          input: {
            ...parsedInitialParams,
            nameContains: 'test',
            sortBy: ListAlertsSortFieldsEnum.CreatedAt,
            sortDir: SortDirEnum.Descending,
            logTypes: [mockedlogType],
            createdAtAfter: '2000-01-29T00:00:00Z',
            createdAtBefore: '2000-01-30T00:00:00Z',
          },
        },
        data: {
          alerts: buildListAlertsResponse({
            alertSummaries: [buildAlertSummary({ title: 'Date Filtered Alert' })],
          }),
        },
      }),
    ];

    const {
      findByText,
      getByLabelText,
      getAllByLabelText,
      getByText,
      findAllByLabelText,
      findByTestId,
      history,
    } = render(<ListAlerts />, {
      initialRoute: `/${initialParams}`,
      mocks,
    });

    // Await for API requests to resolve
    await findByText('Initial Alert');
    await findAllByLabelText('Log Type');

    // Expect the text filter to be empty by default
    const textFilter = getByLabelText('Filter Alerts by text');
    expect(textFilter).toHaveValue('');

    // Change it to something
    fireEvent.change(textFilter, { target: { value: 'test' } });

    // Give a second for the side-effects to kick in
    await waitMs(1);

    // Expect the URL to be updated
    const paramsWithTextFilter = `${initialParams}&nameContains=test`;
    expect(parseParams(history.location.search)).toEqual(parseParams(paramsWithTextFilter));

    // Expect the API request to have fired and a new alert to have returned (verifies API execution)
    await findByText('Text Filtered Alert');

    /* ****************** */

    // Expect the sort dropdown to be empty by default
    const sortFilter = getAllByLabelText('Sort By')[0];
    expect(sortFilter).toHaveValue('');

    // Change its value
    fireClickAndMouseEvents(sortFilter);
    fireClickAndMouseEvents(await findByText('Most Recent'));

    // Give a second for the side-effects to kick in
    await waitMs(1);

    // Expect the URL to be updated
    const paramsWithSortingAndTextFilter = `${paramsWithTextFilter}&sortBy=${ListAlertsSortFieldsEnum.CreatedAt}&sortDir=${SortDirEnum.Descending}`;
    expect(parseParams(history.location.search)).toEqual(parseParams(paramsWithSortingAndTextFilter)); // prettier-ignore

    // Expect the API request to have fired and a new alert to have returned (verifies API execution)
    await findByText('Sorted Alert');

    /* ****************** */

    // Expect the sort dropdown to be empty by default. Empty = "All Types" for this filter.
    const logTypesFilter = getAllByLabelText('Log Type')[0];
    expect(logTypesFilter).toHaveValue('All types');

    // Change its value
    fireEvent.focus(logTypesFilter);
    fireClickAndMouseEvents(await findByText(mockedlogType));

    // Give a second for the side-effects to kick in
    await waitMs(1);

    // Expect the URL to be updated
    const paramsWithSortingAndTextFilterAndLogType = `${paramsWithSortingAndTextFilter}&logTypes[]=${mockedlogType}`;
    expect(parseParams(history.location.search)).toEqual(parseParams(paramsWithSortingAndTextFilterAndLogType)); // prettier-ignore

    // Expect the API request to have fired and a new alert to have returned (verifies API execution)
    await findByText('Log Filtered Alert');

    /* ****************** */

    const startDateFilter = getByLabelText('Date Start');
    const endDateFilter = getByLabelText('Date End');
    expect(startDateFilter).toHaveValue('');
    expect(endDateFilter).toHaveValue('');

    fireClickAndMouseEvents(startDateFilter);
    fireClickAndMouseEvents(await findByText('Last 24 Hours'));
    fireClickAndMouseEvents(getByText('Apply'));

    // Give a second for the side-effects to kick in
    await waitMs(1);

    // Expect the URL to be updated
    const completeParams = `${paramsWithSortingAndTextFilterAndLogType}&createdAtAfter=2000-01-29T00:00:00Z&createdAtBefore=2000-01-30T00:00:00Z`;
    expect(parseParams(history.location.search)).toEqual(parseParams(completeParams));

    // Expect the API request to have fired and a new alert to have returned (verifies API execution)
    await findByText('Date Filtered Alert');

    // Verify that the filters inside the Dropdown are left intact
    fireClickAndMouseEvents(getByText('Filters (4)'));
    const withinDropdown = within(await findByTestId('dropdown-alert-listing-filters'));
    expect(withinDropdown.getByText('Open')).toBeInTheDocument();
    expect(withinDropdown.getByText('Triaged')).toBeInTheDocument();
    expect(withinDropdown.getByText('Info')).toBeInTheDocument();
    expect(withinDropdown.getByText('Medium')).toBeInTheDocument();
    expect(withinDropdown.getByLabelText('Min Events')).toHaveValue(2);
    expect(withinDropdown.getByLabelText('Max Events')).toHaveValue(5);
  });
});
