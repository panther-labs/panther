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
import {
  render,
  waitForElementToBeRemoved,
  buildS3LogIntegration,
  buildSqsLogSourceIntegration,
} from 'test-utils';
import { LogIntegrationsEnum } from 'Source/constants';
import { mockListLogSources } from './graphql/listLogSources.generated';
import ListLogSources from './index';

describe('ListLogSources', () => {
  it('renders a list of compliance cards', async () => {
    const sources = [
      buildSqsLogSourceIntegration({
        integrationId: '1',
        integrationLabel: 'First',
        integrationType: LogIntegrationsEnum.sqs,
      }),
      buildS3LogIntegration({
        integrationId: '2',
        integrationLabel: 'Second',
        integrationType: LogIntegrationsEnum.s3,
      }),
    ];

    const mocks = [mockListLogSources({ data: { listLogIntegrations: sources } })];

    const { getByText, getByAriaLabel } = render(<ListLogSources />, { mocks });

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
