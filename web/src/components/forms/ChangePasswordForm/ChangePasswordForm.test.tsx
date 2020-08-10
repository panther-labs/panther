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
import ChangePasswordForm from './index';

describe('ChangePasswordConfirmForm', () => {
  it('renders the correct fields', () => {
    const { getByLabelText, getByText } = render(<ChangePasswordForm onSuccess={() => {}} />);
    expect(getByLabelText('Current Password')).toBeInTheDocument();
    expect(getByLabelText('New Password')).toBeInTheDocument();
    expect(getByLabelText('Confirm New Password')).toBeInTheDocument();
    expect(getByText('Update password')).toBeInTheDocument();
  });

  it('has proper validation', async () => {
    const { getByLabelText, findByText, getByText, queryByAriaLabel } = render(
      <ChangePasswordForm onSuccess={() => {}} />
    );

    const currentPassword = getByLabelText('Current Password');
    const newPassword = getByLabelText('New Password');
    const newPasswordConfirm = getByLabelText('Confirm New Password');
    const sumbitBtn = getByText('Update password');

    // By default submit should be disabled
    expect(sumbitBtn).toHaveAttribute('disabled');

    // min 12 chars
    // with lower
    let value = 'aaaaaaaaaaaa';
    fireEvent.change(currentPassword, { target: { value } });
    fireEvent.change(newPassword, { target: { value } });
    fireEvent.change(newPasswordConfirm, { target: { value } });
    await waitFor(() => expect(sumbitBtn).toHaveAttribute('disabled'));

    // with upper
    value += 'A';
    fireEvent.change(currentPassword, { target: { value } });
    fireEvent.change(newPassword, { target: { value } });
    fireEvent.change(newPasswordConfirm, { target: { value } });
    await waitFor(() => expect(sumbitBtn).toHaveAttribute('disabled'));

    // with number
    value += '1';
    fireEvent.change(currentPassword, { target: { value } });
    fireEvent.change(newPassword, { target: { value } });
    fireEvent.change(newPasswordConfirm, { target: { value } });
    await waitFor(() => expect(sumbitBtn).toHaveAttribute('disabled'));

    // with symbol
    value += '!';
    fireEvent.change(currentPassword, { target: { value } });
    fireEvent.change(newPassword, { target: { value } });
    fireEvent.change(newPasswordConfirm, { target: { value } });
    await waitFor(() => {
      expect(sumbitBtn).not.toHaveAttribute('disabled');
      expect(queryByAriaLabel('Check is failing')).toBeFalsy();
    });

    // with mismatch
    fireEvent.change(newPasswordConfirm, { target: { value: `${value}??` } });
    fireEvent.blur(newPasswordConfirm);
    expect(await findByText('Passwords must match')).not.toBeNull();
  });

  it('submits the form', async () => {
    const onSuccess = jest.fn();
    const { getByLabelText, getByText, changePassword } = render(
      <ChangePasswordForm onSuccess={onSuccess} />
    );

    // Required from Yup schema validation
    const strongPassword = 'abCDefg123456!@@##';

    const currentPassword = getByLabelText('Current Password');
    const newPassword = getByLabelText('New Password');
    const newPasswordConfirm = getByLabelText('Confirm New Password');
    const sumbitBtn = getByText('Update password');

    fireEvent.change(currentPassword, { target: { value: strongPassword } });
    fireEvent.change(newPassword, { target: { value: strongPassword } });
    fireEvent.change(newPasswordConfirm, { target: { value: strongPassword } });
    fireEvent.click(sumbitBtn);

    await waitFor(() => {
      expect(onSuccess).toHaveBeenCalled();
      expect(changePassword).toHaveBeenCalledWith({
        oldPassword: strongPassword,
        newPassword: strongPassword,
        onSuccess: expect.any(Function),
        onError: expect.any(Function),
      });
    });
  });
});
