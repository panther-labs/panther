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
import { buildUser, fireClickAndMouseEvents, render } from 'test-utils';
import { mockListUsers } from './graphql/listUsers.generated';
import ListUsers from './ListUsers';

const users = [
  buildUser({
    email: 'richardmiles@gmail.com',
    familyName: 'Miles',
    givenName: 'Richard',
    id: '1',
    status: 'CONFIRMED',
  }),
  buildUser({
    email: 'johndoe@gmail.com',
    familyName: 'Doe',
    givenName: 'John',
    id: '2',
    // User hasn't accepted the invitation yet
    status: 'FORCE_CHANGE_PASSWORD',
  }),
];

describe('ListUsers', () => {
  it('shows a placeholder while loading', () => {
    const { getAllByAriaLabel } = render(<ListUsers />);

    const loadingBlocks = getAllByAriaLabel('Loading interface...');
    expect(loadingBlocks.length).toBe(1);
  });

  it('matches snapshot', async () => {
    const mocks = [mockListUsers({ data: { users: [users[0]] } })];

    const { findByText, container } = render(<ListUsers />, { mocks });
    // Check that Invite User button is present
    expect(await findByText('Invite User')).toBeInTheDocument();
    expect(container).toMatchSnapshot();
  });

  it('renders a list of users', async () => {
    const mocks = [mockListUsers({ data: { users } })];

    const { getByText, findByText } = render(<ListUsers />, { mocks });
    // Check that Invite User button is present
    expect(await findByText('Invite User')).toBeInTheDocument();
    // Expect to see a list of all users
    users.forEach(user => {
      expect(getByText(`${user.givenName} ${user.familyName}`)).toBeInTheDocument();
      expect(getByText(user.email)).toBeInTheDocument();
    });
  });

  it('correctly displays user options', async () => {
    const mocks = [mockListUsers({ data: { users } })];

    const { getByText, findByText, findAllByRole } = render(<ListUsers />, { mocks });
    // Find and open first user options
    const userOptions = await findAllByRole('button', { name: 'User Options' });
    fireClickAndMouseEvents(userOptions[0]);
    // Expect to see the correct user options
    expect(await findByText('Edit')).toBeInTheDocument();
    expect(getByText('Force password reset')).toBeInTheDocument();
    expect(await getByText('Delete')).toBeInTheDocument();
    // Close first user options and open second
    fireClickAndMouseEvents(userOptions[0]);
    fireClickAndMouseEvents(userOptions[1]);
    // Expect to see the correct user options
    expect(await findByText('Edit')).toBeInTheDocument();
    expect(getByText('Reinvite user')).toBeInTheDocument();
    expect(getByText('Delete')).toBeInTheDocument();
  });
});
