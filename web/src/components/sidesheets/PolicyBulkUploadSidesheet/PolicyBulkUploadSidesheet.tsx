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

import { Box, Heading, SideSheet, useSnackbar, Text, SideSheetProps, Button, Link } from 'pouncejs';
import React from 'react';
import { ANALYSIS_UPLOAD_DOC_URL } from 'Source/constants';
import { ListPoliciesDocument } from 'Pages/ListPolicies';
import { ListRulesDocument } from 'Pages/ListRules';
import { getOperationName } from 'apollo-utilities';
import { extractErrorMessage } from 'Helpers/utils';
import { useUploadPolicies } from './graphql/uploadPolicies.generated';

export interface PolicyBulkUploadSideSheetProps extends SideSheetProps {
  type: 'policy' | 'rule';
}

const PolicyBulkUploadSideSheet: React.FC<PolicyBulkUploadSideSheetProps> = ({
  type,
  onClose,
  ...rest
}) => {
  // We don't want to expose a file-input to the user, thus we are gonna create a hidden one and
  // map the clicks of a button to the hidden input (as if the user had clicked the hidden input).
  // To do that we need a reference to it
  const isPolicy = type === 'policy';
  const inputRef = React.useRef<HTMLInputElement>(null);
  const { pushSnackbar } = useSnackbar();
  const [bulkUploadPolicies, { loading }] = useUploadPolicies({
    onCompleted: data => {
      onClose();
      pushSnackbar({
        variant: 'success',
        title: `Successfully uploaded ${
          data.uploadPolicies[isPolicy ? 'totalPolicies' : 'totalRules']
        } ${isPolicy ? 'policies' : 'rules'}`,
      });
    },
    onError: error => {
      pushSnackbar({
        variant: 'error',
        duration: 10000,
        title: `Couldn't upload your ${isPolicy ? 'policies' : 'rules'}`,
        description:
          extractErrorMessage(error) || 'An unknown error occurred while during the upload',
      });
    },
  });

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

  return (
    <SideSheet
      aria-labelledby="sidesheet-title"
      aria-describedby="sidesheet-description"
      onClose={onClose}
      {...rest}
    >
      <Box width={400}>
        <Heading mb={8} id="sidesheet-title">
          Upload {isPolicy ? 'Policies' : 'Rules'}
        </Heading>
        <Text color="gray-200" mb={8} id="sidesheet-description">
          Sometimes you don{"'"}t have the luxury of creating {isPolicy ? 'policies' : 'rules'}{' '}
          one-by-one through our lovely editor page. Not to worry, as a way to speed things up, we
          also accept a single Base64-encoded zipfile containing all of your policies.
          <br />
          <br />
          Supposing you have a collection of {isPolicy ? 'policy' : 'rule'} files, simply zip them
          together using any zip method you prefer. You can find a detailed description of the
          process in our{' '}
          <Link external href={ANALYSIS_UPLOAD_DOC_URL}>
            designated docs page
          </Link>
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
        <Button
          disabled={loading}
          loading={loading}
          fullWidth
          onClick={() => inputRef.current.click()}
        >
          {loading ? 'Uploading' : 'Select a file'}
        </Button>
      </Box>
    </SideSheet>
  );
};

export default PolicyBulkUploadSideSheet;
