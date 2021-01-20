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
import { fireEvent, render, waitFor } from 'test-utils';
import * as Yup from 'yup';
import { Box } from 'pouncejs';
import { Formik, Form, Field } from 'formik';
import FormikTextInput from 'Components/fields/TextInput';
import SubmitButton from './index';

const validationSchema = Yup.object().shape({
  text: Yup.string().min(10).required(),
});

const TestForm = ({ onSubmit, initialValues = { text: '' }, ...rest }) => (
  <Box position="relative">
    <Formik
      validationSchema={validationSchema}
      initialValues={initialValues}
      onSubmit={values => {
        onSubmit(values);
      }}
    >
      <Form>
        <Field as={FormikTextInput} placeholder="Write something" name="text" label="Text" />
        <SubmitButton aria-label="SAVE" {...rest}>
          Save
        </SubmitButton>
      </Form>
    </Formik>
  </Box>
);

describe('SubmitButton', () => {
  it('renders', async () => {
    const { container, getByText } = render(<TestForm onSubmit={jest.fn()} />);

    expect(getByText('Save')).toBeInTheDocument();
    expect(container).toMatchSnapshot();
  });

  it('should be disabled by default as long as the form is pristine or invalid', async () => {
    const { getByText, getByLabelText } = render(<TestForm onSubmit={jest.fn()} />);
    const saveButton = getByText('Save');
    const textField = getByLabelText('Text');

    expect(saveButton).toHaveAttribute('disabled');
    // Type an invalid value to the input (less than 10 characters)
    fireEvent.change(textField, { target: { value: 'invalid' } });
    await waitFor(() => expect(saveButton).toHaveAttribute('disabled'));
    // Type a valid value to the input
    fireEvent.change(textField, { target: { value: 'valid text' } });
    await waitFor(() => expect(saveButton).not.toHaveAttribute('disabled'));
  });

  it('should be always enabled if pristine and invalid submission are both enabled', async () => {
    const { getByText, getByLabelText } = render(
      <TestForm onSubmit={jest.fn()} allowPristineSubmission allowInvalidSubmission />
    );

    const saveButton = getByText('Save');
    expect(saveButton).not.toHaveAttribute('disabled');
    fireEvent.change(getByLabelText('Text'), { target: { value: 'invalid' } });
    await waitFor(() => expect(saveButton).not.toHaveAttribute('disabled'));
  });

  it('should be initially enabled if form is valid and pristine submission is allowed', () => {
    const { getByText } = render(
      <TestForm
        onSubmit={jest.fn()}
        allowPristineSubmission
        initialValues={{ text: 'valid text' }}
      />
    );

    expect(getByText('Save')).not.toHaveAttribute('disabled');
  });

  it('should be initially disabled if form is pristine and pristine submission is not allowed', () => {
    const { getByText } = render(
      <TestForm
        onSubmit={jest.fn()}
        allowInvalidSubmission
        initialValues={{ text: 'valid text' }}
      />
    );

    expect(getByText('Save')).toHaveAttribute('disabled');
  });

  it('should be enabled if form is invalid and invalid submission is allowed', async () => {
    const { getByText, getByLabelText } = render(
      <TestForm onSubmit={jest.fn()} allowInvalidSubmission />
    );

    fireEvent.change(getByLabelText('Text'), { target: { value: 'invalid' } });
    await waitFor(() => expect(getByText('Save')).not.toHaveAttribute('disabled'));
  });
});
