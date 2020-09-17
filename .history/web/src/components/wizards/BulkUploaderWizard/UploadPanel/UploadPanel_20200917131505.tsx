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
import { FadeIn } from 'pouncejs';

import { WizardPanel, useWizardContext } from 'Components/Wizard';
import { extractErrorMessage } from 'Helpers/utils';
import { useUploadPolicies } from './graphql/uploadPolicies.generated';

import UploadError from './Error';
import UploadForm from './Upload';
import Processing from './Processing';

const STALE = 'STALE';
const PROCESSING = 'PROCESSING';
const ERROR = 'ERROR';

const UploadPanel: React.FC = () => {
  const controller = new window.AbortController();
  const [uploadingState, setUploadingState] = React.useState(STALE);
  const [errorMsg, setErrorMsg] = React.useState('');
  const { goToNextStep, resetData, setData } = useWizardContext();

  const [bulkUploadPolicies] = useUploadPolicies({
    context: {
      fetchOptions: { signal: controller.signal },
    },
    onCompleted: data => {
      setErrorMsg('');
      console.log(data, 'cb');
      setData(data);
      goToNextStep();
    },
    onError: error => {
      resetData();
      setErrorMsg(
        extractErrorMessage(error) || 'An unknown error occurred while during the upload'
      );
      setUploadingState(ERROR);
    },
  });

  const onAbort = React.useCallback(() => {
    // Abort mutation
    controller.abort();
    // Reset panel data
    resetData();
    // Reset to stale
    setUploadingState(STALE);
  }, [controller, resetData]);

  const onFilesDropped = React.useCallback(
    acceptedFiles => {
      if (!acceptedFiles || acceptedFiles?.length !== 1) {
        return;
      }
      const [file] = acceptedFiles;

      // create a new FileReader instance and read the contents of the file while encoding it as
      // base-64

      const reader = new FileReader();
      reader.readAsDataURL(file);

      // When the read has finished, remove the media-type prefix from the base64-string (that's why
      // this `.split(',')[1]` is happening) and attempt to automatically submit to the server. On a
      // successful submission we want to update our queries since the server will have new
      // policies for us
      reader.addEventListener('load', async () => {
        setUploadingState(PROCESSING);
        try {
          await bulkUploadPolicies({
            awaitRefetchQueries: true,
            variables: {
              input: {
                data: (reader.result as string).split(',')[1],
              },
            },
          });
          // and in case of an error, reset the file input. If we don't do that, then the user can't
          // re-upload the same file he had selected, since the field would never have been cleared.
          // This protects us against just that.
        } catch (err) {
          setErrorMsg('An unknown error occurred while during the upload');
          setUploadingState(ERROR);
        }
      });
    },
    [setUploadingState]
  );

  const restartUploading = React.useCallback(() => {
    setUploadingState(STALE);
    setErrorMsg('');
  }, [setUploadingState, setErrorMsg]);

  return (
    <WizardPanel>
      <FadeIn>
        {uploadingState === STALE && <UploadForm onFilesDropped={onFilesDropped} />}
        {uploadingState === PROCESSING && <Processing onAbort={onAbort} />}
        {uploadingState === ERROR && (
          <UploadError errorMsg={errorMsg} onRestartUploading={restartUploading} />
        )}
      </FadeIn>
    </WizardPanel>
  );
};
export default UploadPanel;
