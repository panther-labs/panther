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
import { act, render, fireEvent } from 'test-utils';
import ForgotPassword from './ForgotPassword';

describe('Forgot password', () => {
  test('it renders the form', async () => {
    const { getByPlaceholderText, getByText } = await render(<ForgotPassword />);
    expect(getByText('Forgot your password?')).toBeInTheDocument();
    expect(
      getByText(
        'By submitting a request, you will receive an email with instructions on how to reset your password'
      )
    ).toBeInTheDocument();
    expect(
      getByText("We'll help you reset your password and get back on track.")
    ).toBeInTheDocument();
    expect(getByPlaceholderText('Enter your company email...')).toBeInTheDocument();
    expect(getByText('Reset Password')).toBeInTheDocument();
  });

  test('it disables the submit button', async () => {
    const { getByText, getByLabelText } = await render(<ForgotPassword />);
    expect(getByText(/Reset Password/i)).toHaveAttribute('disabled');
    await act(async () => {
      await fireEvent.change(getByLabelText(/email/i), { target: { value: 'test@runpanther.io' } });
    });

    expect(getByText(/Reset Password/i)).not.toHaveAttribute('disabled');
  });

  test('it renders the sidebar and the panther branding', async () => {
    const { getByTestId } = await render(<ForgotPassword />);
    expect(getByTestId('auth-page-branding')).toBeInTheDocument();
  });

  test('it renders auth page footer', async () => {
    const { getByText } = await render(<ForgotPassword />);
    expect(getByText('Sign in')).toBeInTheDocument();
  });
});
