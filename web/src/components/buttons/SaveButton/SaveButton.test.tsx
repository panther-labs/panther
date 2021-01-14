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
import { render, fireEvent, waitFor } from 'test-utils';
import { Formik, Form, Field } from 'formik';
import FormikTextInput from 'Components/fields/TextInput';
import SaveButton from './index';

const TestForm = ({ onSubmit, ...rest }) => (
  <Formik
    initialValues={{
      test: '',
    }}
    onSubmit={values => {
      onSubmit(values);
    }}
  >
    {() => (
      <Form>
        <Field as={FormikTextInput} label="test" name="test" id="test" />
        <SaveButton aria-label="submit button" {...rest}>
          Submit
        </SaveButton>
      </Form>
    )}
  </Formik>
);

describe('CancelButton', () => {
  it('renders', () => {
    const onSubmit = jest.fn();
    const { container } = render(<TestForm onSubmit={onSubmit} />);
    expect(container).toMatchSnapshot();
  });

  it('allows form submission', async () => {
    const onSubmit = jest.fn();
    const { findByLabelText, getByAriaLabel } = render(<TestForm onSubmit={onSubmit} />);

    const submit = getByAriaLabel('submit button');
    const input = (await findByLabelText('test')) as HTMLInputElement;

    expect(submit).toHaveAttribute('disabled');
    // Make the button available
    await waitFor(() => {
      fireEvent.change(input, {
        target: {
          value: 'test me',
        },
      });
    });

    expect(submit).not.toHaveAttribute('disabled');
    await waitFor(() => {
      fireEvent.click(submit);
    });

    expect(onSubmit).toHaveBeenCalled();
  });
});
