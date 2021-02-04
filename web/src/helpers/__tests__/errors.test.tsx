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

import { render, fireEvent, waitMs } from 'test-utils';
import React from 'react';
import { Button } from 'pouncejs';
import { logError } from 'Helpers/errors';
import * as Sentry from '@sentry/browser';
import { ERROR_REPORTING_CONSENT_STORAGE_KEY } from 'Source/constants';

interface TestProps {
  error: Error;
}

const TestComponent: React.FC<TestProps> = ({ error }) => {
  return (
    <Button
      onClick={() => {
        logError(error);
      }}
    >
      Button click
    </Button>
  );
};

describe('Sentry Reporting', () => {
  it('should report error to Sentry', async () => {
    const error = Error('Dummy Error');
    const { getByText } = render(<TestComponent error={error} />);

    const btn = getByText('Button click');

    fireEvent.click(btn);
    await waitMs(1);
    expect(Sentry.init).toHaveBeenCalled();
    expect(Sentry.captureException).toHaveBeenCalledWith(error);
  });

  it('should NOT report error to Sentry', async () => {
    localStorage.setItem(ERROR_REPORTING_CONSENT_STORAGE_KEY, 'false');
    const error = Error('Dummy Error');
    const { getByText } = render(<TestComponent error={error} />);

    const btn = getByText('Button click');

    fireEvent.click(btn);
    await waitMs(1);
    expect(Sentry.init).not.toBeCalled();
    expect(Sentry.captureException).not.toBeCalled();
  });
});
