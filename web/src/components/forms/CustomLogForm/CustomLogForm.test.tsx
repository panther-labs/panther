/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import React from 'react';
import { render, fireEvent, waitMs } from 'test-utils';
import CustomLogForm from './CustomLogForm';

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
    await waitMs(10);
    expect(submitBtn).toHaveAttribute('disabled');

    fireEvent.change(schemaField, { target: { value: 'test' } });
    await waitMs(210); // wait for debounce to apply the value to <Formik>
    expect(submitBtn).toHaveAttribute('disabled');

    fireEvent.change(nameField, { target: { value: 'Custom.Test' } });
    await waitMs(10);
    expect(submitBtn).not.toHaveAttribute('disabled');

    fireEvent.change(descriptionField, { target: { value: 'test' } });
    fireEvent.change(referenceUrlField, { target: { value: 'test' } });
    await waitMs(10);
    expect(submitBtn).toHaveAttribute('disabled');

    fireEvent.change(referenceUrlField, { target: { value: 'https://test.com' } });
    await waitMs(10);
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

    await waitMs(210); // wait for debounce to apply the value to <Formik> + perform validation

    expect(getByText('Save log')).not.toHaveAttribute('disabled');

    fireEvent.click(getByText('Save log'));
    await waitMs(10); // wait for debounce + validation

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

    await waitMs(210); // wait for debounce to apply the value to <Formik>

    fireEvent.click(getByText('Validate Syntax'));

    expect(await findByText('root')).toBeInTheDocument();
    expect(getByText('requires property "version"')).toBeInTheDocument();
    expect(getByText('requires property "fields"')).toBeInTheDocument();
    expect(getByText('Validate Again')).toBeInTheDocument();
  });
});
