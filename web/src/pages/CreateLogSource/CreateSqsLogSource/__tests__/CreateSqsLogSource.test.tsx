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
import { render, fireEvent } from 'test-utils';
import CreateSqsLogSource from 'Pages/CreateLogSource/CreateSqsLogSource';

test('renders SQS creation wizard', async () => {
  const sqsInput = {
    integrationLabel: 'SQS',
    sqsConfig: {
      logTypes: ['AWS.ALB'],
      allowedSourceArns: ['source'],
      allowedPrincipalArns: ['principal'],
    },
  };

  const { getByText, queryByText, container } = render(<CreateSqsLogSource />);

  // Expect to see a loading interface
  const configurationPanel = getByText("Let's start with the basics");
  expect(configurationPanel).toBeTruthy();
  const integrationLabelField = container.querySelector('input[name="integrationLabel"]');
  const logTypesField = container.querySelector('input[name="logTypes"]');
  const allowedPrincipalArnsField = container.querySelector('input[name="allowedPrincipalArns"]');
  const allowedSourceArnsField = container.querySelector('input[name="allowedSourceArns"]');
  const nextButton = getByText('Next');
  // Expecting input elements and button to be rendered
  expect(integrationLabelField).not.toBeNull();
  expect(logTypesField).not.toBeNull();
  expect(allowedPrincipalArnsField).not.toBeNull();
  expect(allowedSourceArnsField).not.toBeNull();
  expect(nextButton).toBeDisabled();

  // Adding input to fields
  fireEvent.change(integrationLabelField, { target: { value: sqsInput.integrationLabel } });
  fireEvent.change(logTypesField, { target: { value: sqsInput.sqsConfig.logTypes } });
  fireEvent.change(allowedPrincipalArnsField, {
    target: { value: sqsInput.sqsConfig.allowedPrincipalArns },
  });
  fireEvent.change(allowedSourceArnsField, {
    target: { value: sqsInput.sqsConfig.allowedSourceArns },
  });

  expect(getByText('Next').closest('button')).not.toBeDisabled();
  expect(queryByText('Save Source')).toBeNull();
  // Triggering event for Next step
  fireEvent.click(getByText('Next'));
  expect(getByText('Save Source')).toBeDefined();
});
