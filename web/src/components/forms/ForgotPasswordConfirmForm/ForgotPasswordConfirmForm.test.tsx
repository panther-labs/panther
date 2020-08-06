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
