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
import { render, fireEvent, buildUser, buildUserInfo, waitMs } from 'test-utils';
import { getUserDisplayName } from 'Helpers/utils';
import { mockEditUser } from 'Components/sidesheets/EditUserSidesheet';
import ProfileSettingsModal from './index';

describe('ProfileSettingsModal', () => {
  it('renders two tabs', () => {
    const onClose = jest.fn();
    const { getAllByRole } = render(<ProfileSettingsModal open onClose={onClose} />);

    const tabs = getAllByRole('tab');
    expect(tabs[0]).toHaveTextContent('Profile Settings');
    expect(tabs[1]).toHaveTextContent('Account Security');
  });

  it('renders name, email and inputs for editing name when in Profile settings tab', () => {
    const onClose = jest.fn();
    const { getByText, getByLabelText, userInfo } = render(
      <ProfileSettingsModal open onClose={onClose} />
    );

    expect(getByText('logged in as')).toBeTruthy();
    expect(getByText(getUserDisplayName(userInfo))).toBeTruthy();
    expect(getByText(userInfo.email)).toBeTruthy();

    const firstNameInput = getByLabelText('First Name') as HTMLInputElement;
    const lastNameInput = getByLabelText('Last Name') as HTMLInputElement;

    expect(firstNameInput.value).toEqual(userInfo.givenName);
    expect(lastNameInput.value).toEqual(userInfo.familyName);
  });

  test("can correctly update a user's name when in Profile settings tab", async () => {
    const userInfo = buildUserInfo();
    const newFirstName = 'newFirstName';
    const newLastName = 'newLastName';

    const mocks = [
      mockEditUser({
        variables: {
          input: {
            id: userInfo.id,
            givenName: newFirstName,
            familyName: newLastName,
          },
        },
        data: {
          updateUser: buildUser({ givenName: newFirstName, familyName: newLastName }),
        },
      }),
    ];

    const onClose = jest.fn();
    const { getByText, getByLabelText, findByText } = render(
      <ProfileSettingsModal open onClose={onClose} />,
      { mocks, userInfo }
    );

    // initially the submit button should be disabled
    const submitButton = getByText('Save Changes');
    expect(submitButton).toHaveAttribute('disabled');

    const firstNameInput = getByLabelText('First Name') as HTMLInputElement;
    const lastNameInput = getByLabelText('Last Name') as HTMLInputElement;

    fireEvent.change(firstNameInput, { target: { value: newFirstName } });
    fireEvent.change(lastNameInput, { target: { value: newLastName } });
    fireEvent.click(submitButton);

    // wait for snackbar
    await findByText('User profile updated successfully');

    // expect modal to have closed
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('renders a password change form which works correctly when in Account Security tab', async () => {
    const passwordValue = 'asdasdasdasd123A!';

    const onClose = jest.fn();
    const { getByText, getByLabelText, changePassword, signOut } = render(
      <ProfileSettingsModal open onClose={onClose} />
    );

    // Go to account security tab
    const accountSecurityTab = getByText('Account Security');
    fireEvent.click(accountSecurityTab);

    // Find the password fields
    const currentPasswordInput = getByLabelText('Current Password') as HTMLInputElement;
    const newPasswordInput = getByLabelText('New Password') as HTMLInputElement;
    const newPasswordConfirmInput = getByLabelText('Confirm New Password') as HTMLInputElement;

    // initially the submit button should be disabled
    const submitButton = getByText('Update password');
    expect(submitButton).toHaveAttribute('disabled');

    // Change the password fields
    fireEvent.change(currentPasswordInput, { target: { value: passwordValue } });
    fireEvent.change(newPasswordInput, { target: { value: passwordValue } });
    fireEvent.change(newPasswordConfirmInput, { target: { value: passwordValue } });

    fireEvent.click(submitButton);

    // wait for callbacks
    await waitMs(1);

    expect(changePassword).toHaveBeenCalled();
    expect(signOut).toHaveBeenCalled();
    expect(onClose).toHaveBeenCalled();
  });
});
