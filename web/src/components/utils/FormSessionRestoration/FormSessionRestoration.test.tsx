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
  await waitMs(300);

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
  await waitMs(300);

  // Click the cancel
  fireEvent.click(getByText('Cancel'));
  expect(sessionStorage.__STORE__).toEqual({});

  // remove the form
  unmount();

  // re-instate the  form
  const { getByLabelText: getByRemountedLabelText } = render(<TestForm />);

  // wait a bit for any React effects to finish
  await waitMs(100);

  // wait until the value has beeen restored  (will time-out if the value is not restored)
  const inputElement = getByRemountedLabelText('Text');
  expect(inputElement).toHaveValue('');
});
