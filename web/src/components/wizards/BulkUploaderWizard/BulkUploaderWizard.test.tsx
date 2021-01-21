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
import { mockUploadDetections } from './UploadPanel/graphql/uploadDetections.generated';
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

  it('shows an error screen', async () => {
    const file = new File([JSON.stringify({ ping: true })], 'bulkfile.zip', {
      type: 'zip',
    });

    const { getByTestId, getByText } = render(<BulkUploaderWizard />);

    expect(getByText('Bulk Upload your rules, policies & python modules!')).toBeInTheDocument();
    expect(getByText('Select file')).toBeInTheDocument();
    expect(getByText('Drag & Drop your .zip file here')).toBeInTheDocument();

    const uploadInput = getByTestId('input-upload');

    Object.defineProperty(uploadInput, 'files', {
      value: [file],
    });
    fireEvent.change(uploadInput);

    // Processing
    await waitFor(() => getByTestId('processing-indicator'));

    // Error screen
    expect(getByText('Could not upload your rules')).toBeInTheDocument();
    expect(getByText('Try Again')).toBeInTheDocument();

    const retryButton = getByText('Try Again');
    fireEvent.click(retryButton);

    // Return to uploading screen
    await waitFor(() => getByText('Bulk Upload your rules, policies & python modules!'));
    expect(getByText('Select file')).toBeInTheDocument();
  });

  it('allows selecting and uploading file', async () => {
    const mocks = [
      mockUploadDetections({
        data: {
          uploadDetections: {
            totalPolicies: 113,
            modifiedPolicies: 0,
            newPolicies: 0,
            totalRules: 110,
            modifiedRules: 0,
            newRules: 0,
            totalGlobals: 4,
            newGlobals: 0,
            modifiedGlobals: 0,
            totalDataModels: 5,
            newDataModels: 1,
            modifiedDataModels: 1,
          },
        },
        variables: { input: { data: 'eyJwaW5nIjp0cnVlfQ==' } },
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

    // Processing state
    const processinIndicator = await waitFor(() => getByTestId('processing-indicator'));
    expect(processinIndicator).toBeInTheDocument();

    const successfulIndicator = await waitFor(() => getByTestId('success-indicator'));

    expect(successfulIndicator).toBeInTheDocument();
    expect(getByText('Python Modules')).toBeInTheDocument();
    expect(getByText('Rules')).toBeInTheDocument();
    expect(getByText('Policies')).toBeInTheDocument();
    expect(getByText('Data Models')).toBeInTheDocument();
    expect(getByText('Upload another')).toBeInTheDocument();
  });
});
