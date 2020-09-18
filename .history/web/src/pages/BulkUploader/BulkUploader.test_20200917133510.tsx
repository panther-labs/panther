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
  fireEvent,
  buildComplianceIntegration,
  waitFor,
  waitMs,
  buildUpdateComplianceIntegrationInput,
} from 'test-utils';
import BulkUploader from './BulkUploader';

// Components/wizards/BulkUploaderWizard/UploadPanel/graphql/uploadPolicies.generated.ts

describe('BulkUploader', () => {
  it('renders', async () => {
    const { getByText } = render(<BulkUploader />);

    expect(getByText('Bulk Upload your rules, policies & python modules!')).toBeInTheDocument();
    expect(getByText('Select file')).toBeInTheDocument();
    expect(getByText('Drag & Drop your .zip file here')).toBeInTheDocument();
    expect(getByText('designated docs page')).toBeInTheDocument();
    expect(
      getByText(
        `If you have a collection of rules, policies, or python modules files, simply zip them together using any zip method you prefer and upload them here`
      )
    ).toBeInTheDocument();
  });

  it('allows dropping a file', async () => {
    const { getByText } = render(<BulkUploader />);
  });
});
