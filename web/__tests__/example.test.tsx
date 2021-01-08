/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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
import { buildUser, render, waitForElementToBeRemoved } from 'test-utils';
import ListUsersPage, { mockListUsers } from 'Pages/Users';

test('renders a list of users in the users page', async () => {
  const users = [buildUser()];
  const mocks = [mockListUsers({ data: { users } })];

  const { getByText, getByAriaLabel } = render(<ListUsersPage />, { mocks });

  // Expect to see a loading interface
  const loadingInterfaceElement = getByAriaLabel('Loading interface...');
  expect(loadingInterfaceElement).toBeTruthy();

  // Wait for it to not exist anymore
  await waitForElementToBeRemoved(loadingInterfaceElement);

  // Expect to see a list of names and emails
  users.forEach(user => {
    expect(getByText(`${user.givenName} ${user.familyName}`)).toBeTruthy();
    expect(getByText(user.email)).toBeTruthy();
  });
});
