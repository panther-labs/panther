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
import { render, screen } from 'test-utils';
import PolicyForm from 'Components/forms/PolicyForm';
import { ListRemediationsDocument } from 'Components/forms/PolicyForm/graphql/listRemediations.generated';
import { AddPolicyInput } from 'Generated/schema';
import { DEFAULT_POLICY_FUNCTION } from 'Source/constants';
import { act } from 'react-dom/test-utils';

test('render a header', async () => {
  const initialValues: Required<AddPolicyInput> = {
    body: DEFAULT_POLICY_FUNCTION,
    autoRemediationId: '',
    autoRemediationParameters: '{}',
    description: '',
    displayName: '',
    enabled: true,
    id: '',
    outputIds: [],
    reference: '',
    resourceTypes: [],
    runbook: '',
    severity: null,
    suppressions: [],
    tags: [],
    tests: [],
  };

  const mocks = [
    {
      request: {
        query: ListRemediationsDocument,
      },
      result: {
        data: {
          remediations: '{}',
        },
      },
    },
  ];

  render(<PolicyForm initialValues={initialValues} onSubmit={() => {}} />, { mocks });

  await act(async () => screen.findByText('Auto Remediation Settings'));
  expect(true).toBeTruthy();
});
