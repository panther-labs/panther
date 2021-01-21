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

import { render, fireEvent, waitMs } from 'test-utils';
import React from 'react';
import { Button, Box } from 'pouncejs';
import FormSessionRestoration from 'Components/utils/FormSessionRestoration';
import { Field, Form, Formik } from 'formik';
import FormikTextInput from 'Components/fields/TextInput';

const sessionId = 'sessionId';

interface TestFormValues {
  text: string;
}

jest.mock('lodash/debounce', () => jest.fn(fn => fn));
// A dummy test form
const TestForm: React.FC = () => (
  <Formik<TestFormValues> initialValues={{ text: '' }} onSubmit={() => {}}>
    <FormSessionRestoration sessionId={sessionId}>
      {({ clearFormSession }) => (
        <Box>
          <Form>
            <Field as={FormikTextInput} placeholder="Write somehting" name="text" label="Text" />
          </Form>
          <Button onClick={clearFormSession}>Cancel</Button>
        </Box>
      )}
    </FormSessionRestoration>
  </Formik>
);

test('correctly stores form values to session', async () => {
  const testValue = 'test-value';

  const { getByLabelText, unmount } = render(<TestForm />);

  const textInput = getByLabelText('Text');
  fireEvent.change(textInput, { target: { value: testValue } });
  expect(textInput).toHaveValue(testValue);

  // wait for debounce to kick in
  await waitMs(1);

  // remove the form
  unmount();

  // re-instate the  form
  const { findByDisplayValue } = render(<TestForm />);

  // wait until the value has been restored  (will time-out if the value is not restored)
  const inputElement = await findByDisplayValue(testValue);
  expect(inputElement).toHaveValue(testValue);
});

test('correctly clears the session when `clearFormSession` is called', async () => {
  const testValue = 'test-value';

  const { getByLabelText, getByText, unmount } = render(<TestForm />);

  const textInput = getByLabelText('Text');
  fireEvent.change(textInput, { target: { value: testValue } });
  expect(textInput).toHaveValue(testValue);

  // wait for debounce to kick in
  await waitMs(1);
  expect(sessionStorage.setItem).toHaveBeenCalledWith(
    sessionId,
    JSON.stringify({ text: testValue })
  );

  // Click the cancel
  fireEvent.click(getByText('Cancel'));
  expect(sessionStorage.length).toBe(0);

  // remove the form
  unmount();

  // re-instate the  form
  const { getByLabelText: getByRemountedLabelText } = render(<TestForm />);

  // wait a bit for any React effects to finish
  await waitMs(1);

  // wait until the value has been restored  (will time-out if the value is not restored)
  const inputElement = getByRemountedLabelText('Text');
  expect(inputElement).toHaveValue('');
});
