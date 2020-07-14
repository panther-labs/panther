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
import { buildUser, render, generateRandomArray, waitForElementToBeRemoved } from 'test-utils';
import Breadcrumbs from 'Components/Breadcrumbs';
import urls from 'Source/urls';
import ListUsersPage, { mockListUsers } from 'Pages/Users';

test('renders correct  breadcrumbs', async () => {
  const { container } = render(<Breadcrumbs />, { initialRoute: urls.compliance.policies.list() });

  expect(container).toHaveTextContent('Home');
  expect(container).toHaveTextContent('Policies');
});

test('renders a list of users in the users page', async () => {
  const randomUsers = generateRandomArray(() => buildUser(), 1, 5);
  const mocks = [mockListUsers({ data: { users: randomUsers } })];

  const { getByText, getByAriaLabel } = render(<ListUsersPage />, { mocks });

  // Expect to see a loading interface
  const loadingInterfaceElement = getByAriaLabel('Loading interface...');
  expect(loadingInterfaceElement).toBeTruthy();

  // Wait for it to not exist anymore
  await waitForElementToBeRemoved(loadingInterfaceElement);

  // Expect to see a list of names and emails
  randomUsers.forEach(user => {
    expect(getByText(`${user.givenName} ${user.familyName}`)).toBeTruthy();
    expect(getByText(user.email)).toBeTruthy();
  });
});
