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

import { render, waitForElementToBeRemoved, buildComplianceIntegration } from 'test-utils';
import React from 'react';
import { mockListComplianceSources } from './graphql/listComplianceSources.generated';
import ListComplianceSources from './index';

describe('ListComplianceSources', () => {
  it('renders a list of compliance cards', async () => {
    const sources = [
      buildComplianceIntegration({ integrationId: '1', integrationLabel: 'First' }),
      buildComplianceIntegration({ integrationId: '2', integrationLabel: 'Second' }),
    ];

    const mocks = [mockListComplianceSources({ data: { listComplianceIntegrations: sources } })];

    const { getByText, getByAriaLabel } = render(<ListComplianceSources />, { mocks });

    // Expect to see a loading interface
    const loadingInterfaceElement = getByAriaLabel('Loading interface...');
    expect(loadingInterfaceElement).toBeInTheDocument();

    // Wait for it to not exist anymore
    await waitForElementToBeRemoved(loadingInterfaceElement);

    // Expect to see a list of names and emails
    sources.forEach(source => {
      expect(getByText(source.integrationLabel)).toBeInTheDocument();
    });
  });
});
