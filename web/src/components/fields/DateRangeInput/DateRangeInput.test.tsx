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
import ReactDOM from 'react-dom';
import mockDate from 'mockdate';
import { render, fireEvent, waitFor } from 'test-utils';
import dayjs from 'dayjs';
import { Box } from 'pouncejs';
import { Formik, Form } from 'formik';
import FormikDateRangeInput from './index';

const TestForm = ({ onSubmit, initialValues = {}, ...rest }) => (
  <Box position="relative">
    <Formik
      initialValues={initialValues}
      onSubmit={values => {
        onSubmit(values);
      }}
    >
      <Form>
        <FormikDateRangeInput
          alignment="right"
          withPresets
          withTime
          labelStart="Date Start"
          labelEnd="Date End"
          nameStart="start"
          nameEnd="end"
          {...rest}
        />
        <button type="submit">Submit</button>
      </Form>
    </Formik>
  </Box>
);

beforeAll(() => {
  (ReactDOM.createPortal as jest.MockedFunction<any>) = jest.fn(element => {
    return element;
  });
});

afterAll(() => {
  (ReactDOM.createPortal as jest.MockedFunction<any>).mockClear();
});

beforeEach(() => {
  mockDate.set(new Date('November 03, 2020 15:00:00 GMT +2'));
});

afterEach(() => {
  mockDate.reset();
});

describe('FormikDateRangeInput', () => {
  it('renders', async () => {
    const { container, getByLabelText } = render(<TestForm onSubmit={jest.fn()} />);

    fireEvent.click(getByLabelText('Date End'));
    expect(container).toMatchSnapshot();
  });

  it('allows the user to select local mockDate.reset(), but still submits dates in UTC ', async () => {
    const onSubmit = jest.fn();
    const { getByLabelText, getByText } = render(<TestForm onSubmit={onSubmit} />);

    fireEvent.click(getByLabelText('Date End'));
    fireEvent.click(getByLabelText('Last 24 Hours'));
    fireEvent.click(getByText('Apply'));
    fireEvent.click(getByText('Submit'));

    await waitFor(() => {
      expect(onSubmit).toHaveBeenCalledWith({
        start: '2020-11-02T13:00:00.000Z',
        end: '2020-11-03T13:00:59.999Z',
      });
    });
  });

  it('correctly parses dates & displays picker in local time when `timezone` is `local`', async () => {
    const onSubmit = jest.fn();

    const fakeDayjs = dayjs('January 01, 2020 15:00:00 GMT+2');
    const start = fakeDayjs.toISOString();
    const end = fakeDayjs.add(10, 'day').toISOString();

    const { getByText, getByLabelText } = render(
      <TestForm initialValues={{ start, end }} format="MM/DD/YYYY HH:mm" onSubmit={onSubmit} />
    );

    // Jest tests run in UTC timezone so we expect local timezone to be UTC
    expect(getByLabelText('Date Start')).toHaveValue('01/01/2020 13:00');
    expect(getByLabelText('Date End')).toHaveValue('01/11/2020 13:00');

    fireEvent.click(getByText('Submit'));

    await waitFor(() => {
      expect(onSubmit).toHaveBeenCalledWith({
        start: '2020-01-01T13:00:00.000Z',
        end: '2020-01-11T13:00:00.000Z',
      });
    });
  });
});
