import React from 'react';
import { fireEvent, render, waitFor } from 'test-utils';
import * as Yup from 'yup';
import { Box } from 'pouncejs';
import { Formik, Form, Field } from 'formik';
import FormikTextInput from 'Components/fields/TextInput';
import SubmitButton from './index';

const validationSchema = Yup.object().shape({
  text: Yup.string().min(10),
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
});
