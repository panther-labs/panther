import React from 'react';
import { render, fireEvent, act, waitFor } from 'test-utils';
import ForgotPasswordForm from './ForgotPasswordForm';

const renderForm = () => render(<ForgotPasswordForm />);

describe('ForgotPasswordForm', () => {
  it('renders', async () => {
    const { getByText } = renderForm();
    expect(await getByText('Email')).toBeInTheDocument();
  });

  it('has proper validation', async () => {
    const { findByLabelText, findByText } = await renderForm();
    await act(async () => {
      const emailInput = await findByLabelText('Email');
      await fireEvent.change(emailInput, {
        target: { value: 'invalidemail' },
      });

      await fireEvent.blur(emailInput);
    });

    await waitFor(() => {
      expect(findByText('Needs to be a valid email')).not.toBeNull();
    });
  });

  it('submits the form', async () => {
    const { findByLabelText, findByText, forgotPassword } = await renderForm();
    const email = 'runner1@runpanther.io';
    await act(async () => {
      const emailInput = await findByLabelText('Email');
      const sumbitBtn = await findByText('Reset Password');

      await fireEvent.change(emailInput, {
        target: { value: email },
      });
      await fireEvent.click(sumbitBtn);
    });

    await waitFor(() => {
      expect(forgotPassword).toHaveBeenCalledWith({
        email,
        onError: expect.any(Function),
        onSuccess: expect.any(Function),
      });
    });
  });
});
