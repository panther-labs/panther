/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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

import { Box, Heading, SideSheet, useSnackbar, Text, Alert } from 'pouncejs';
import React from 'react';
import { SubmitButton } from 'Components/Buttons';

import useSidesheet from 'Hooks/useSidesheet';
import { PANTHER_SCHEMA_DOCS_LINK } from 'Source/constants';
import { ListPoliciesDocument } from 'Pages/ListPolicies';
import { ListRulesDocument } from 'Pages/ListRules';
import { getOperationName } from '@apollo/client/utilities/graphql/getFromAST';
import { extractErrorMessage } from 'Helpers/utils';
import { useUploadPolicies } from './graphql/uploadPolicies.generated';

export interface PolicyBulkUploadSideSheetProps {
  type: 'policy' | 'rule';
}

const PolicyBulkUploadSideSheet: React.FC<PolicyBulkUploadSideSheetProps> = ({ type }) => {
  // We don't want to expose a file-input to the user, thus we are gonna create a hidden one and
  // map the clicks of a button to the hidden input (as if the user had clicked the hidden input).
  // To do that we need a reference to it
  const isPolicy = type === 'policy';
  const inputRef = React.useRef<HTMLInputElement>(null);
  const { pushSnackbar } = useSnackbar();
  const { hideSidesheet } = useSidesheet();
  const [bulkUploadPolicies, { data, loading, error }] = useUploadPolicies();

  // This is the function that gets triggered each time the user selects a new file. The event
  // is not needed since we can't read the selected file from it (we need the input reference)
  const handleFileChange = () => {
    // get the file from the file input (it's not contained in the event payload unfortunately)
    const file = inputRef.current.files[0];
    if (!file) {
      return;
    }

    // create a new FileReader instance and read the contents of the file while encoding it as
    // base-64
    const reader = new FileReader();
    reader.readAsDataURL(file);

    // When the read has finished, remove the media-type prefix from the base64-string (that's why
    // this `.split(',')[1]` is happening) and attempt to automatically submit to the server. On a
    // successful submission we want to update our queries since the server will have new
    // policies for us
    reader.addEventListener('load', async () => {
      try {
        await bulkUploadPolicies({
          awaitRefetchQueries: true,
          refetchQueries: [getOperationName(isPolicy ? ListPoliciesDocument : ListRulesDocument)],
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
        inputRef.current.value = '';
      }
    });
  };

  // On a successful submit, add a snackbar to inform the user
  React.useEffect(() => {
    if (data) {
      hideSidesheet();
      pushSnackbar({
        variant: 'success',
        title: `Successfully uploaded ${
          data.uploadPolicies[isPolicy ? 'totalPolicies' : 'totalRules']
        } ${isPolicy ? 'policies' : 'rules'}`,
      });
    }
  }, [data]);

  return (
    <SideSheet open onClose={hideSidesheet}>
      <Box width={400}>
        <Heading size="medium" mb={8}>
          Upload {isPolicy ? 'Policies' : 'Rules'}
        </Heading>
        <Text size="large" color="grey300" mb={8} is="p">
          Sometimes you don{"'"}t have the luxury of creating {isPolicy ? 'policies' : 'rules'}{' '}
          one-by-one through our lovely editor page. Not to worry, as a way to speed things up, we
          also accept a single Base64-encoded zipfile containing all of your policies.
          <br />
          <br />
          Supposing you have a collection of {isPolicy ? 'policy' : 'rule'} files, simply zip them
          together using any zip method you prefer. You can find a detailed description of the
          process in our{' '}
          <a
            href={`${PANTHER_SCHEMA_DOCS_LINK}/policies/uploading`}
            target="_blank"
            rel="noopener noreferrer"
          >
            designated docs page
          </a>
          .
          <br />
          <br />
          Ready to use this feature? Click on the button below to select a zipfile to upload...
        </Text>
        <input
          type="file"
          accept="zip,application/octet-stream,application/zip,application/x-zip,application/x-zip-compressed"
          ref={inputRef}
          hidden
          onChange={handleFileChange}
        />
        {error && (
          <Alert
            variant="error"
            title="An error has occurred"
            description={
              extractErrorMessage(error) ||
              'An unknown error occured while attempting to upload your policies'
            }
            mb={6}
          />
        )}
        <SubmitButton
          disabled={loading}
          submitting={loading}
          width={1}
          onClick={() => inputRef.current.click()}
        >
          {loading ? 'Uploading...' : 'Select a file'}
        </SubmitButton>
      </Box>
    </SideSheet>
  );
};

export default PolicyBulkUploadSideSheet;
