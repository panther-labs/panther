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
import { DEFAULT_SENSITIVE_VALUE } from 'Source/constants';
import SensitiveTextInput from './index';

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
        <Field as={SensitiveTextInput} label="test" name="test" id="test" {...rest} />
        <button type="submit">Submit</button>
      </Form>
    )}
  </Formik>
);

describe('SensitiveTextInput', () => {
  it('renders', async () => {
    const onSubmit = jest.fn();
    const { container } = render(<TestForm onSubmit={onSubmit} />);
    expect(container).toMatchSnapshot();
  });

  it('renders without masked values on demand', async () => {
    const onSubmit = jest.fn();
    const { container } = render(<TestForm shouldMask={false} onSubmit={onSubmit} />);
    expect(container).toMatchSnapshot();
  });

  it('renders a default value', async () => {
    const onSubmit = jest.fn();
    const { findByLabelText } = render(<TestForm onSubmit={onSubmit} />);
    const input = (await findByLabelText('test')) as HTMLInputElement;
    expect(input.value).toBe(DEFAULT_SENSITIVE_VALUE);
  });

  it('shows a tooltip', async () => {
    const onSubmit = jest.fn();
    const { findByLabelText, findByText } = render(<TestForm onSubmit={onSubmit} />);
    const input = await findByLabelText('test');
    fireEvent.mouseOver(input);
    expect(
      await findByText('This information is sensitive and we hide it for your own protection')
    ).toBeInTheDocument();
  });

  it('submits the proper values', async () => {
    const onSubmit = jest.fn();
    const { findByLabelText, container } = render(<TestForm onSubmit={onSubmit} />);
    const submit = container.querySelector('button[type="submit"]');
    const input = (await findByLabelText('test')) as HTMLInputElement;
    const sensitiveValue = 'this-is-an-actual-value';
    expect(input.value).toBe(DEFAULT_SENSITIVE_VALUE);

    await waitFor(() => {
      fireEvent.change(input, {
        target: {
          value: sensitiveValue,
        },
      });
    });
    await waitFor(() => {
      fireEvent.click(submit);
    });

    expect(input.value).toBe(sensitiveValue);
    expect(onSubmit).toHaveBeenCalledWith({ test: sensitiveValue });
  });
});
