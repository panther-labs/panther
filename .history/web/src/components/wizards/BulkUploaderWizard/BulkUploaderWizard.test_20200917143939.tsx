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
import { mockUploadPolicies } from './UploadPanel/graphql/uploadPolicies.generated';
import BulkUploaderWizard from './BulkUploaderWizard';

describe('BulkUploaderWizard', () => {
  it('renders', async () => {
    const { getByText } = render(<BulkUploaderWizard />);

    expect(getByText('Bulk Upload your rules, policies & python modules!')).toBeInTheDocument();
    expect(getByText('Select file')).toBeInTheDocument();
    expect(getByText('Drag & Drop your .zip file here')).toBeInTheDocument();
    expect(
      getByText(
        `If you have a collection of rules, policies, or python modules files, simply zip them together using any zip method you prefer and upload them here`
      )
    ).toBeInTheDocument();
  });

  it('allows dropping a file', async () => {
    const mocks = [
      mockUploadPolicies({
        data: {
          uploadPolicies: {
            totalPolicies: 113,
            modifiedPolicies: 0,
            newPolicies: 0,
            totalRules: 110,
            modifiedRules: 0,
            newRules: 0,
            totalGlobals: 4,
            newGlobals: 0,
            modifiedGlobals: 0,
          },
        },
        variables: { input: { data: 'panther' } },
      }),
    ];
    const file = new File([JSON.stringify({ ping: true })], 'bulkfile.zip', {
      type: 'zip',
    });

    const { getByTestId, getByText } = render(<BulkUploaderWizard />, { mocks });
    const uploadInput = getByTestId('input-upload');

    Object.defineProperty(uploadInput, 'files', {
      value: [file],
    });
    fireEvent.change(uploadInput);
    const indicator = await waitFor(() => getByTestId('processing-indicator'));

    expect(indicator).toBeInTheDocument();
    expect(getByText('Your file is being processed…')).toBeInTheDocument();
    expect(getByText('Cancel')).toBeInTheDocument();
  });
});
