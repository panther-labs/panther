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
  buildListRulesResponse,
  render,
  fireEvent,
  within,
  fireClickAndMouseEvents,
  waitMs,
  buildRuleSummary,
} from 'test-utils';
import { ListRulesSortFieldsEnum, SeverityEnum, SortDirEnum } from 'Generated/schema';
import { queryStringOptions } from 'Hooks/useUrlParams';
import MockDate from 'mockdate';
import queryString from 'query-string';
import { mockListAvailableLogTypes } from 'Source/graphql/queries';
import { mockListRules } from './graphql/listRules.generated';
import ListRules from './ListRules';

// Mock debounce so it just executes the callback instantly
jest.mock('lodash/debounce', () => jest.fn(fn => fn));

const parseParams = (search: string) => queryString.parse(search, queryStringOptions);

describe('ListRules', () => {
  beforeAll(() => {
    // https://github.com/boblauer/MockDate#example
    // Forces a fixed resolution on `Date.now()`. Used for the DateRangePicker
    MockDate.set('1/30/2000');
  });

  afterAll(() => {
    MockDate.reset();
  });

  it('shows a placeholder while loading', () => {
    const { getAllByAriaLabel } = render(<ListRules />);

    const loadingBlocks = getAllByAriaLabel('Loading interface...');
    expect(loadingBlocks.length).toBeGreaterThan(1);
  });

  it('can correctly boot from URL params', async () => {
    const mockedlogType = 'AWS.ALB';
    const initialParams =
      `?enabled=true` +
      `&logTypes[]=${mockedlogType}` +
      `&nameContains=test` +
      `&severity=${SeverityEnum.Info}` +
      `&sortBy=${ListRulesSortFieldsEnum.LastModified}` +
      `&sortDir=${SortDirEnum.Descending}` +
      `&tags[]=soc&tags[]=soc-2` +
      `&page=1`;

    const parsedInitialParams = parseParams(initialParams);
    const mocks = [
      mockListAvailableLogTypes({
        data: {
          listAvailableLogTypes: {
            logTypes: [mockedlogType],
          },
        },
      }),
      mockListRules({
        variables: {
          input: parsedInitialParams,
        },
        data: {
          rules: buildListRulesResponse({
            rules: [buildRuleSummary({ displayName: 'Test Rule' })],
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
    } = render(<ListRules />, {
      initialRoute: `/${initialParams}`,
      mocks,
    });

    // Await for API requests to resolve
    await findByText('Test Rule');
    await findAllByLabelText('Log Type');

    // Verify filter values outside of Dropdown
    expect(getByLabelText('Filter Rules by text')).toHaveValue('test');
    expect(getByText('soc')).toBeInTheDocument();
    expect(getByText('soc-2')).toBeInTheDocument();
    expect(getAllByLabelText('Sort By')[0]).toHaveValue('Most Recently Modified');
    expect(getAllByLabelText('Log Type')[0]).toHaveValue(mockedlogType);

    // Verify filter value inside the Dropdown
    fireClickAndMouseEvents(getByText('Filters (2)'));
    const withinDropdown = within(await findByTestId('dropdown-rule-listing-filters'));
    expect(withinDropdown.getAllByLabelText('Severity')[0]).toHaveValue('Info');
    expect(withinDropdown.getAllByLabelText('Enabled')[0]).toHaveValue('Yes');
  });

  it('correctly applies & resets dropdown filters', async () => {
    const mockedlogType = 'AWS.ALB';
    const initialParams =
      `?logTypes[]=${mockedlogType}` +
      `&nameContains=test` +
      `&sortBy=${ListRulesSortFieldsEnum.LastModified}` +
      `&sortDir=${SortDirEnum.Descending}` +
      `&tags[]=soc&tags[]=soc-2` +
      `&page=1`;

    const parsedInitialParams = parseParams(initialParams);
    const mocks = [
      mockListAvailableLogTypes({
        data: {
          listAvailableLogTypes: {
            logTypes: [mockedlogType],
          },
        },
      }),
      mockListRules({
        variables: {
          input: parsedInitialParams,
        },
        data: {
          rules: buildListRulesResponse({
            rules: [buildRuleSummary({ displayName: 'Initial Rule' })],
          }),
        },
      }),
      mockListRules({
        variables: {
          input: {
            ...parsedInitialParams,
            enabled: true,
            severity: SeverityEnum.Info,
          },
        },
        data: {
          rules: buildListRulesResponse({
            rules: [buildRuleSummary({ displayName: 'Filtered Rule' })],
          }),
        },
      }),
      mockListRules({
        variables: {
          input: parsedInitialParams,
        },
        data: {
          rules: buildListRulesResponse({
            rules: [buildRuleSummary({ displayName: 'Initial Rule' })],
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
    } = render(<ListRules />, {
      initialRoute: `/${initialParams}`,
      mocks,
    });

    // Wait for all API requests to resolve
    await findByText('Initial Rule');
    await findAllByLabelText('Log Type');

    // Open the Dropdown
    fireClickAndMouseEvents(getByText('Filters'));
    let withinDropdown = within(await findByTestId('dropdown-rule-listing-filters'));

    // Modify all the filter values
    fireClickAndMouseEvents(withinDropdown.getAllByLabelText('Severity')[0]);
    fireEvent.click(withinDropdown.getByText('Info'));
    fireClickAndMouseEvents(withinDropdown.getAllByLabelText('Enabled')[0]);
    fireEvent.click(withinDropdown.getByText('Yes'));

    // Expect nothing to have changed until "Apply is pressed"
    expect(parseParams(history.location.search)).toEqual(parseParams(initialParams));

    // Apply the new values of the dropdown filters
    fireEvent.click(withinDropdown.getByText('Apply Filters'));

    // Wait for side-effects to apply
    await waitMs(1);

    // Expect URL to have changed to mirror the filter updates
    const updatedParams = `${initialParams}&enabled=true&severity=${SeverityEnum.Info}`;
    expect(parseParams(history.location.search)).toEqual(parseParams(updatedParams));

    // Await for the new API request to resolve
    await findByText('Filtered Rule');

    // Expect the rest of the filters to be intact (to not have changed in any way)
    expect(getByLabelText('Filter Rules by text')).toHaveValue('test');
    expect(getByText('soc')).toBeInTheDocument();
    expect(getByText('soc-2')).toBeInTheDocument();
    expect(getAllByLabelText('Sort By')[0]).toHaveValue('Most Recently Modified');
    expect(getAllByLabelText('Log Type')[0]).toHaveValue(mockedlogType);

    // Open the Dropdown (again)
    fireClickAndMouseEvents(getByText('Filters (2)'));
    withinDropdown = within(await findByTestId('dropdown-rule-listing-filters'));

    // Clear all the filter values
    fireEvent.click(withinDropdown.getByText('Clear Filters'));

    // Verify that they are cleared
    expect(withinDropdown.getAllByLabelText('Severity')[0]).not.toHaveValue('Info');
    expect(withinDropdown.getAllByLabelText('Enabled')[0]).not.toHaveValue('Yes');

    // Expect the URL to not have changed until "Apply Filters" is clicked
    expect(parseParams(history.location.search)).toEqual(parseParams(updatedParams));

    // Apply the changes from the "Clear Filters" button
    fireEvent.click(withinDropdown.getByText('Apply Filters'));

    // Wait for side-effects to apply
    await waitMs(1);

    // Expect the URL to reset to its original values
    expect(parseParams(history.location.search)).toEqual(parseParams(initialParams));

    // Expect the rest of the filters to STILL be intact (to not have changed in any way)
    expect(getByLabelText('Filter Rules by text')).toHaveValue('test');
    expect(getByText('soc')).toBeInTheDocument();
    expect(getByText('soc-2')).toBeInTheDocument();
    expect(getAllByLabelText('Sort By')[0]).toHaveValue('Most Recently Modified');
    expect(getAllByLabelText('Log Type')[0]).toHaveValue(mockedlogType);
  });

  it('correctly updates filters & sorts on every change outside of the dropdown', async () => {
    const mockedlogType = 'AWS.ALB';
    const initialParams = `?enabled=true&severity=${SeverityEnum.Info}&page=1`;

    const parsedInitialParams = parseParams(initialParams);
    const mocks = [
      mockListAvailableLogTypes({
        data: {
          listAvailableLogTypes: {
            logTypes: [mockedlogType],
          },
        },
      }),
      mockListRules({
        variables: {
          input: parsedInitialParams,
        },
        data: {
          rules: buildListRulesResponse({
            rules: [buildRuleSummary({ displayName: 'Initial Rule' })],
          }),
        },
      }),
      mockListRules({
        variables: {
          input: { ...parsedInitialParams, nameContains: 'test' },
        },
        data: {
          rules: buildListRulesResponse({
            rules: [buildRuleSummary({ displayName: 'Text Filtered Rule' })],
          }),
        },
      }),
      mockListRules({
        variables: {
          input: {
            ...parsedInitialParams,
            nameContains: 'test',
            sortBy: ListRulesSortFieldsEnum.LastModified,
            sortDir: SortDirEnum.Descending,
          },
        },
        data: {
          rules: buildListRulesResponse({
            rules: [buildRuleSummary({ displayName: 'Sorted Rule' })],
          }),
        },
      }),
      mockListRules({
        variables: {
          input: {
            ...parsedInitialParams,
            nameContains: 'test',
            sortBy: ListRulesSortFieldsEnum.LastModified,
            sortDir: SortDirEnum.Descending,
            logTypes: [mockedlogType],
          },
        },
        data: {
          rules: buildListRulesResponse({
            rules: [buildRuleSummary({ displayName: 'Log Filtered Rule' })],
          }),
        },
      }),
      mockListRules({
        variables: {
          input: {
            ...parsedInitialParams,
            nameContains: 'test',
            sortBy: ListRulesSortFieldsEnum.LastModified,
            sortDir: SortDirEnum.Descending,
            logTypes: [mockedlogType],
            tags: ['soc', 'soc-2'],
          },
        },
        data: {
          rules: buildListRulesResponse({
            rules: [buildRuleSummary({ displayName: 'Tag Filtered Rule' })],
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
    } = render(<ListRules />, {
      initialRoute: `/${initialParams}`,
      mocks,
    });

    // Await for API requests to resolve
    await findByText('Initial Rule');
    await findAllByLabelText('Log Type');

    // Expect the text filter to be empty by default
    const textFilter = getByLabelText('Filter Rules by text');
    expect(textFilter).toHaveValue('');

    // Change it to something
    fireEvent.change(textFilter, { target: { value: 'test' } });

    // Give a second for the side-effects to kick in
    await waitMs(1);

    // Expect the URL to be updated
    const paramsWithTextFilter = `${initialParams}&nameContains=test`;
    expect(parseParams(history.location.search)).toEqual(parseParams(paramsWithTextFilter));

    // Expect the API request to have fired and a new alert to have returned (verifies API execution)
    await findByText('Text Filtered Rule');

    /* ****************** */

    // Expect the sort dropdown to be empty by default
    const sortFilter = getAllByLabelText('Sort By')[0];
    expect(sortFilter).toHaveValue('');

    // Change its value
    fireClickAndMouseEvents(sortFilter);
    fireClickAndMouseEvents(await findByText('Most Recently Modified'));

    // Give a second for the side-effects to kick in
    await waitMs(1);

    // Expect the URL to be updated
    const paramsWithSortingAndTextFilter = `${paramsWithTextFilter}&sortBy=${ListRulesSortFieldsEnum.LastModified}&sortDir=${SortDirEnum.Descending}`;
    expect(parseParams(history.location.search)).toEqual(parseParams(paramsWithSortingAndTextFilter)); // prettier-ignore

    // Expect the API request to have fired and a new alert to have returned (verifies API execution)
    await findByText('Sorted Rule');

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
    await findByText('Log Filtered Rule');

    /* ****************** */

    const tagsFilter = getAllByLabelText('Tags')[0];
    expect(tagsFilter).toHaveValue('');

    fireEvent.change(tagsFilter, { target: { value: 'soc' } });
    fireEvent.keyDown(tagsFilter, { key: 'Enter' });
    fireEvent.change(tagsFilter, { target: { value: 'soc-2' } });
    fireEvent.keyDown(tagsFilter, { key: 'Enter' });

    // Give a second for the side-effects to kick in
    await waitMs(1);

    // Expect the URL to be updated
    const completeParams = `${paramsWithSortingAndTextFilterAndLogType}&tags[]=soc&tags[]=soc-2`;
    expect(parseParams(history.location.search)).toEqual(parseParams(completeParams));

    // Expect the API request to have fired and a new alert to have returned (verifies API execution)
    await findByText('Tag Filtered Rule');

    // Verify that the filters inside the Dropdown are left intact
    fireClickAndMouseEvents(getByText('Filters (2)'));
    const withinDropdown = within(await findByTestId('dropdown-rule-listing-filters'));
    expect(withinDropdown.getAllByLabelText('Severity')[0]).toHaveValue('Info');
    expect(withinDropdown.getAllByLabelText('Enabled')[0]).toHaveValue('Yes');
  });
});
