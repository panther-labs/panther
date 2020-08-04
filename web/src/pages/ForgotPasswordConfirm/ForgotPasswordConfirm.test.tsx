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
