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
import ForgotPasswordForm from './ForgotPasswordForm';

const renderForm = () => render(<ForgotPasswordForm />);

describe('ForgotPasswordForm', () => {
  it('renders', () => {
    const { getByText } = renderForm();
    expect(getByText('Email')).toBeInTheDocument();
  });

  it('has proper validation', async () => {
    const { getByLabelText, findByText } = renderForm();

    const emailInput = getByLabelText('Email');
    fireEvent.change(emailInput, { target: { value: 'invalidemail' } });
    fireEvent.blur(emailInput);

    await waitFor(() => {
      expect(findByText('Needs to be a valid email')).not.toBeNull();
    });
  });

  it('submits the form', async () => {
    const { getByLabelText, getByText, forgotPassword } = renderForm();
    const email = 'runner1@runpanther.io';
    const emailInput = getByLabelText('Email');
    const sumbitBtn = getByText('Reset Password');

    fireEvent.change(emailInput, { target: { value: email } });
    fireEvent.click(sumbitBtn);

    await waitFor(() => {
      expect(forgotPassword).toHaveBeenCalledWith({
        email,
        onError: expect.any(Function),
        onSuccess: expect.any(Function),
      });
    });
  });
});
