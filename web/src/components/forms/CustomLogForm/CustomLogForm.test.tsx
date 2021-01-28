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
import { render, fireEvent, waitMs } from 'test-utils';
import CustomLogForm from './CustomLogForm';

jest.mock('lodash/debounce', () => jest.fn(fn => fn));

const emptyInitialValues = {
  name: '',
  description: '',
  referenceUrl: '',
  schema: '',
};

describe('CustomLogForm', () => {
  it('correctly validates metadata', async () => {
    const { getByText, getByLabelText, getByPlaceholderText } = render(
      <CustomLogForm initialValues={emptyInitialValues} onSubmit={jest.fn()} />
    );

    const submitBtn = getByText('Save log');
    expect(submitBtn).toHaveAttribute('disabled');

    const nameField = getByLabelText('* Name');
    const descriptionField = getByLabelText('Description');
    const referenceUrlField = getByLabelText('Reference URL');
    const schemaField = getByPlaceholderText('# Write your schema in YAML here...');

    fireEvent.change(nameField, { target: { value: 'test' } });
    await waitMs(1);
    expect(submitBtn).toHaveAttribute('disabled');

    fireEvent.change(schemaField, { target: { value: 'test' } });
    await waitMs(1);
    expect(submitBtn).toHaveAttribute('disabled');

    fireEvent.change(nameField, { target: { value: 'Custom.Test' } });
    await waitMs(1);
    expect(submitBtn).not.toHaveAttribute('disabled');

    fireEvent.change(descriptionField, { target: { value: 'test' } });
    fireEvent.change(referenceUrlField, { target: { value: 'test' } });
    await waitMs(1);
    expect(submitBtn).toHaveAttribute('disabled');

    fireEvent.change(referenceUrlField, { target: { value: 'https://test.com' } });
    await waitMs(1);
    expect(submitBtn).not.toHaveAttribute('disabled');
  });

  it('boots correctly with initial data', () => {
    const { getByLabelText, getByPlaceholderText } = render(
      <CustomLogForm
        initialValues={{
          name: 'Custom.Test',
          description: 'test-description',
          referenceUrl: 'https://test.com',
          schema: 'test-schema',
        }}
        onSubmit={jest.fn()}
      />
    );

    const nameField = getByLabelText('* Name');
    const descriptionField = getByLabelText('Description');
    const referenceUrlField = getByLabelText('Reference URL');
    const schemaField = getByPlaceholderText('# Write your schema in YAML here...');

    expect(nameField).toHaveValue('Custom.Test');
    expect(descriptionField).toHaveValue('test-description');
    expect(referenceUrlField).toHaveValue('https://test.com');
    expect(schemaField).toHaveValue('test-schema');
  });

  it('submits with correct data', async () => {
    const onSubmit = jest.fn();
    const { getByText, getByLabelText, getByPlaceholderText } = render(
      <CustomLogForm initialValues={emptyInitialValues} onSubmit={onSubmit} />
    );

    fireEvent.change(getByLabelText('* Name'), { target: { value: 'Custom.Test' } });
    fireEvent.change(getByLabelText('Description'), { target: { value: 'test-description' } });
    fireEvent.change(getByLabelText('Reference URL'), { target: { value: 'https://test.com' } });
    fireEvent.change(getByPlaceholderText('# Write your schema in YAML here...'), {
      target: { value: 'test-schema' },
    });

    await waitMs(1);

    expect(getByText('Save log')).not.toHaveAttribute('disabled');

    fireEvent.click(getByText('Save log'));
    await waitMs(1); // wait for debounce + validation

    expect(onSubmit).toHaveBeenCalledTimes(1);
    expect(onSubmit).toHaveBeenCalledWith(
      {
        name: 'Custom.Test',
        description: 'test-description',
        referenceUrl: 'https://test.com',
        schema: 'test-schema',
      },
      expect.any(Object)
    );
  });

  it('correctly validates the JSON schema', async () => {
    const { getByText, getByPlaceholderText, findByText } = render(
      <CustomLogForm initialValues={emptyInitialValues} onSubmit={jest.fn()} />
    );

    fireEvent.change(getByPlaceholderText('# Write your schema in YAML here...'), {
      target: { value: '{}' },
    });

    await waitMs(1); // wait for debounce to apply the value to <Formik>

    fireEvent.click(getByText('Validate Syntax'));

    expect(await findByText('root')).toBeInTheDocument();
    expect(getByText('requires property "version"')).toBeInTheDocument();
    expect(getByText('requires property "fields"')).toBeInTheDocument();
    expect(getByText('Validate Again')).toBeInTheDocument();
  });
});
