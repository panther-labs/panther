import React from 'react';
import { render, fireEvent, within } from 'test-utils';
import { getUserDisplayName } from 'Helpers/utils';
import ProfileIcon from './index';

test('renders correct initials', () => {
  const { container, userInfo } = render(<ProfileIcon />);

  const initials = userInfo.givenName[0] + userInfo.familyName[0];
  expect(container).toHaveTextContent(initials);
});

test('opens menu on click with correct entries', () => {
  const { getByAriaLabel, userInfo, getByRole } = render(<ProfileIcon />);

  // Click on the initials button
  fireEvent.mouseDown(getByAriaLabel('Toggle User Menu'));

  // Find proper static data
  const menuElement = getByRole('menu');
  expect(menuElement).toHaveTextContent(getUserDisplayName(userInfo));
  expect(menuElement).toHaveTextContent(userInfo.email);

  // Find proper buttons
  const { getByText: getByTextWithinMenu } = within(menuElement);
  expect(getByTextWithinMenu('Profile Settings')).toBeTruthy();
  expect(getByTextWithinMenu('Log Out')).toBeTruthy();
});

test('Shows profile settings on menu entry click', () => {
  const { getByAriaLabel, getByText } = render(<ProfileIcon />);

  // Click on the initials button
  fireEvent.mouseDown(getByAriaLabel('Toggle User Menu'));
  fireEvent.click(getByText('Profile Settings'));

  // Expect a dialog with some entries
  const sidebarElement = getByAriaLabel('Profile & Account Settings');
  expect(sidebarElement).toHaveAttribute('role', 'dialog');
});

test('Calls SignOut on menu entry click', () => {
  const { getByAriaLabel, signOut, getByText } = render(<ProfileIcon />);

  // Click on the initials button
  fireEvent.mouseDown(getByAriaLabel('Toggle User Menu'));
  fireEvent.click(getByText('Log Out'));

  expect(signOut).toHaveBeenCalledTimes(1);
});
