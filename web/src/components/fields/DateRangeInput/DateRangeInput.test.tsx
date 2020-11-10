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
  mockDate.set(new Date('November 03, 2020 15:00:00'));
});

afterEach(() => {
  mockDate.reset();
});

const month = 10;
const year = 2020;
const day = 1;
const starting = dayjs().date(day).month(month).year(year).hour(1).minute(2);
const ending = starting.add(10, 'day');

describe('FormikDateRangeInput', () => {
  it('renders', async () => {
    const onSubmit = jest.fn();
    const { container, findByLabelText, getByAriaLabel } = render(<TestForm onSubmit={onSubmit} />);

    const inputFrom = await findByLabelText('Date End');
    await fireEvent.click(inputFrom);
    await waitFor(() => {
      expect(getByAriaLabel('Last Month')).toBeTruthy();
    });
    expect(container).toMatchSnapshot();
  });

  it('allows UTC formatting by default', async () => {
    const onSubmit = jest.fn();
    const { getByAriaLabel, findByLabelText, findByText } = render(
      <TestForm onSubmit={onSubmit} />
    );
    const inputFrom = await findByLabelText('Date End');
    await fireEvent.click(inputFrom);
    await waitFor(() => {
      expect(getByAriaLabel('Last 24 Hours')).toBeTruthy();
    });
    const preset = await findByLabelText('Last 24 Hours');
    await waitFor(() => {
      fireEvent.click(preset);
    });
    const dummyFormSubmit = await findByText('Submit');
    const submitBtn = await findByText('Apply');
    await waitFor(() => {
      fireEvent.click(submitBtn);
      fireEvent.click(dummyFormSubmit);
    });
    expect(onSubmit).toHaveBeenCalled();
    expect(onSubmit).toHaveBeenCalledWith({
      start: '2020-11-02T15:00:00Z',
      end: '2020-11-03T15:00:00Z',
    });
  });

  it('parses the dates in UTC format', async () => {
    const onSubmit = jest.fn();
    const start = starting.format('YYYY-MM-DDTHH:mm:ss[Z]');
    const end = ending.format('YYYY-MM-DDTHH:mm:ss[Z]');
    const { getByAriaLabel, findByLabelText, findByText } = render(
      <TestForm initialValues={{ start, end }} onSubmit={onSubmit} />
    );
    const inputFrom = await findByLabelText('Date End');
    await fireEvent.click(inputFrom);
    await waitFor(() => {
      expect(getByAriaLabel('Last Month')).toBeTruthy();
    });
    const preset = await findByLabelText('Last Month');
    const submitBtn = await findByText('Apply');

    const dummyFormSubmit = await findByText('Submit');
    await waitFor(() => {
      fireEvent.click(preset);
    });
    await fireEvent.click(submitBtn);
    await waitFor(() => {
      fireEvent.click(dummyFormSubmit);
    });
    expect(onSubmit).toHaveBeenCalled();
    expect(onSubmit).toHaveBeenCalledWith({
      start: '2020-10-03T15:00:00Z',
      end: '2020-11-03T15:00:00Z',
    });
  });
});
