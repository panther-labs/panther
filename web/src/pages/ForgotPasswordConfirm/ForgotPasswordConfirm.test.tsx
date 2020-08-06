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
import { render } from 'test-utils';
import ForgotPasswordConfirm from './ForgotPasswordConfirm';

describe('ForgotPasswordConfirm', () => {
  test('it renders nonthing when query or token are not in place', async () => {
    const { getByText } = await render(<ForgotPasswordConfirm />);
    expect(getByText('Something seems off...')).toBeInTheDocument();
    expect(getByText('Are you sure that the URL you followed is valid?')).toBeInTheDocument();
  });

  test('it renders the form', async () => {
    const { getByText } = await render(<ForgotPasswordConfirm />, {
      initialRoute: '/?email=test@runpanther.io&token=token',
    });

    expect(getByText(/Update password/i)).toBeInTheDocument();
    expect(getByText(/Confirm New Password/i)).toBeInTheDocument();
  });
});
