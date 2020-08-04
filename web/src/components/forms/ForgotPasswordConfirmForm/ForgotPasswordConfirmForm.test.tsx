import React from 'react';
import { render, fireEvent, act, waitFor } from 'test-utils';
import ForgotPasswordConfirmForm from './ForgotPasswordConfirmForm';

const defaultEmail = 'example@runpanther.io';
const defaultToken = 'xxx-xxx';

const renderForm = ({ email = defaultEmail, token = defaultToken } = {}) =>
  render(<ForgotPasswordConfirmForm email={email} token={token} />);

describe('ForgotPasswordConfirmForm', () => {
  it('renders', async () => {
    const { getByText } = renderForm();
    expect(await getByText('New Password')).toBeInTheDocument();
    expect(await getByText('Confirm New Password')).toBeInTheDocument();
    expect(await getByText('Update password')).toBeInTheDocument();
  });

  it('has proper validation', async () => {
    const { findByLabelText, findByText } = await renderForm();

    await act(async () => {
      const newPassword = await findByLabelText('New Password');
      const newPasswordConfirm = await findByLabelText('Confirm New Password');
      await fireEvent.change(newPassword, {
        target: { value: 'xxxx' },
      });
      await fireEvent.blur(newPassword);
      await fireEvent.change(newPasswordConfirm, {
        target: { value: 'yyyy' },
      });
      await fireEvent.blur(newPasswordConfirm);
    });
    expect(await findByText('Passwords must match')).not.toBeNull();
  });

  it('submits the form', async () => {
    const { findByLabelText, findByText, resetPassword } = await renderForm();
    // Required from Yup schema validation
    const strongPassword = 'abCDefg123456!@@##';

    await act(async () => {
      const newPassword = await findByLabelText('New Password');
      const newPasswordConfirm = await findByLabelText('Confirm New Password');
      const sumbitBtn = await findByText('Update password');

      await fireEvent.change(newPassword, {
        target: { value: strongPassword },
      });
      await fireEvent.blur(newPassword);
      await fireEvent.change(newPasswordConfirm, {
        target: { value: strongPassword },
      });
      await fireEvent.click(sumbitBtn);
    });

    await waitFor(() => {
      expect(resetPassword).toHaveBeenCalledWith({
        newPassword: strongPassword,
        email: defaultEmail,
        token: defaultToken,
        onError: expect.any(Function),
        onSuccess: expect.any(Function),
      });
    });
  });
});
