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
  render,
  waitFor,
  fireEvent,
  waitMs,
  fireClickAndMouseEvents,
  buildListAvailableLogTypesResponse,
} from 'test-utils';
import { mockListAvailableLogTypes } from 'Source/graphql/queries';
import DataModelForm from './DataModelForm';

jest.mock('lodash/debounce', () => jest.fn(fn => fn));

describe('DataModelForm', () => {
  it('can add & remove mappings', () => {
    const initialValues = {
      id: '',
      displayName: '',
      logType: null,
      enabled: true,
      mappings: [{ name: '', method: '', path: '' }],
      body: '',
    };

    const { getByAriaLabel, getAllByLabelText } = render(
      <DataModelForm initialValues={initialValues} onSubmit={jest.fn()} />
    );
    expect(getAllByLabelText('Name')).toHaveLength(1);
    expect(getAllByLabelText('Field Path')).toHaveLength(1);
    expect(getAllByLabelText('Field Method')).toHaveLength(1);

    fireEvent.click(getByAriaLabel('Add a new mapping'));

    expect(getAllByLabelText('Name')).toHaveLength(2);
    expect(getAllByLabelText('Field Path')).toHaveLength(2);
    expect(getAllByLabelText('Field Method')).toHaveLength(2);

    fireEvent.click(getByAriaLabel('Remove mapping'));

    expect(getAllByLabelText('Name')).toHaveLength(1);
    expect(getAllByLabelText('Field Path')).toHaveLength(1);
    expect(getAllByLabelText('Field Method')).toHaveLength(1);
  });

  it('does not allow both `path` & `method` on a mapping', async () => {
    const initialValues = {
      id: '',
      displayName: '',
      logType: null,
      enabled: true,
      mappings: [{ name: '', method: '', path: '' }],
      body: '',
    };

    const { queryAllByText, getByLabelText } = render(
      <DataModelForm initialValues={initialValues} onSubmit={jest.fn()} />
    );

    fireEvent.change(getByLabelText('Name'), { target: { value: 'test' } });
    fireEvent.change(getByLabelText('Field Method'), { target: { value: '' } });

    await waitMs(1);
    expect(queryAllByText("You shouldn't provide both a path & method")).toBeEmpty();

    fireEvent.change(getByLabelText('Field Path'), { target: { value: 'test' } });

    await waitMs(1);
    expect(queryAllByText("You shouldn't provide both a path & method")).toBeEmpty();
  });

  it('correctly allows the user to add information and calls `onSubmit` with the proper payload', async () => {
    const initialValues = {
      id: '',
      displayName: '',
      logType: null,
      enabled: true,
      mappings: [{ name: '', method: '', path: '' }],
      body: '',
    };

    const onSubmit = jest.fn();

    const mocks = [
      mockListAvailableLogTypes({
        data: {
          listAvailableLogTypes: buildListAvailableLogTypesResponse({
            logTypes: ['AWS.ALB', 'AWS.S3'],
          }),
        },
      }),
    ];

    const {
      getByText,
      getByLabelText,
      getAllByLabelText,
      findByText,
      getByAriaLabel,
      getByPlaceholderText,
    } = render(<DataModelForm initialValues={initialValues} onSubmit={onSubmit} />, { mocks });

    const submitBtn = getByText('Save');
    expect(submitBtn).toHaveAttribute('disabled');

    fireEvent.change(getByLabelText('Display Name'), { target: { value: 'test-name' } });
    await waitMs(1);
    expect(submitBtn).toHaveAttribute('disabled');

    fireEvent.change(getByLabelText('ID'), { target: { value: 'test-id' } });
    await waitMs(1);
    expect(submitBtn).toHaveAttribute('disabled');

    fireEvent.change(getAllByLabelText('Log Type')[0], { target: { value: 'AWS.ALB' } });
    fireClickAndMouseEvents(await findByText('AWS.ALB'));
    await waitMs(1);
    expect(submitBtn).toHaveAttribute('disabled');

    fireEvent.click(getByPlaceholderText('Toggle Enabled'));
    await waitMs(1);
    expect(submitBtn).toHaveAttribute('disabled');

    fireEvent.change(getAllByLabelText('Name')[0], { target: { value: 'test-field-name-1' } });
    fireEvent.change(getAllByLabelText('Field Path')[0], {
      target: { value: 'test-field-path-1' },
    });

    fireEvent.click(getByAriaLabel('Add a new mapping'));

    fireEvent.change(getAllByLabelText('Name')[1], { target: { value: 'test-field-name-2' } });
    fireEvent.change(getAllByLabelText('Field Method')[1], {
      target: { value: 'test-field-method-2' },
    });

    await waitMs(1);
    expect(submitBtn).not.toHaveAttribute('disabled');

    fireEvent.click(getByAriaLabel('Toggle Python Editor visibility'));
    fireEvent.change(getByPlaceholderText('# Enter the body of this mapping...'), {
      target: { value: 'test-body' },
    });

    // wait for editor's debounce
    await waitMs(1);
    expect(submitBtn).not.toHaveAttribute('disabled');

    fireEvent.click(submitBtn);

    await waitFor(() =>
      expect(onSubmit).toHaveBeenCalledWith(
        {
          displayName: 'test-name',
          id: 'test-id',
          logType: 'AWS.ALB',
          enabled: false,
          mappings: [
            { name: 'test-field-name-1', method: '', path: 'test-field-path-1' },
            { name: 'test-field-name-2', method: 'test-field-method-2', path: '' },
          ],
          body: 'test-body',
        },
        expect.toBeObject()
      )
    );
  });

  it('boots correctly with initial data', () => {
    const initialValues = {
      id: 'test-id',
      displayName: 'test-name',
      logType: 'AWS.ALB',
      enabled: false,
      mappings: [
        { name: 'test-field-name-1', method: 'test-field-method-1', path: 'test-field-path-1' },
        { name: 'test-field-name-2', method: 'test-field-method-2', path: 'test-field-path-2' },
      ],
      body: 'test-body',
    };

    const mocks = [
      mockListAvailableLogTypes({
        data: {
          listAvailableLogTypes: buildListAvailableLogTypesResponse({
            logTypes: ['AWS.ALB', 'AWS.S3'],
          }),
        },
      }),
    ];

    const { getByLabelText, getAllByLabelText, getByText } = render(
      <DataModelForm initialValues={initialValues} onSubmit={jest.fn()} />,
      { mocks }
    );

    expect(getByLabelText('Display Name')).toHaveValue('test-name');
    expect(getByLabelText('ID')).toHaveValue('test-id');
    expect(getAllByLabelText('Log Type')[0]).toHaveValue('AWS.ALB');
    expect(getByText('OFF')).toBeInTheDocument();

    initialValues.mappings.forEach((mapping, index) => {
      expect(getAllByLabelText('Name')[index]).toHaveValue(mapping.name);
      expect(getAllByLabelText('Field Method')[index]).toHaveValue(mapping.method);
      expect(getAllByLabelText('Field Path')[index]).toHaveValue(mapping.path);
    });
  });
});
