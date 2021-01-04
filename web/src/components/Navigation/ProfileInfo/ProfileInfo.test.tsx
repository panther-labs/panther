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
import { render, fireEvent, within } from 'test-utils';
import { getUserDisplayName } from 'Helpers/utils';
import ProfileInfo from './index';

test('renders correct initials and name', () => {
  const { container, userInfo } = render(<ProfileInfo />);

  const initials = userInfo.givenName[0] + userInfo.familyName[0];
  const name = `${userInfo.givenName[0]}. ${userInfo.familyName}`;
  expect(container).toHaveTextContent(initials);
  expect(container).toHaveTextContent(name);
});

test('opens menu on click with correct entries', () => {
  const { getByAriaLabel, userInfo, getByRole } = render(<ProfileInfo />);

  // Click on the initials button
  fireEvent.mouseDown(getByAriaLabel('Toggle User Menu'));

  // Find proper static data
  const menuElement = getByRole('tooltip');
  expect(menuElement).toHaveTextContent(getUserDisplayName(userInfo));
  expect(menuElement).toHaveTextContent(userInfo.email);

  // Find proper buttons
  const { getByText: getByTextWithinMenu } = within(menuElement);
  expect(getByTextWithinMenu('Profile Settings')).toBeTruthy();
  expect(getByTextWithinMenu('Log Out')).toBeTruthy();
});

test('Shows profile settings on menu entry click', () => {
  const { getByAriaLabel, getByText } = render(<ProfileInfo />);

  // Click on the initials button
  fireEvent.mouseDown(getByAriaLabel('Toggle User Menu'));
  fireEvent.click(getByText('Profile Settings'));

  // Expect a dialog with some entries
  const modalElement = getByAriaLabel('Profile & Account Settings');
  expect(modalElement).toHaveAttribute('role', 'dialog');
});

test('Calls SignOut on menu entry click', () => {
  const { getByAriaLabel, signOut, getByText } = render(<ProfileInfo />);

  // Click on the initials button
  fireEvent.mouseDown(getByAriaLabel('Toggle User Menu'));
  fireEvent.click(getByText('Log Out'));

  expect(signOut).toHaveBeenCalledTimes(1);
});
