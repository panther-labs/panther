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

import * as React from 'react';
import { useMutation, gql } from '@apollo/client';
import { Field, Formik } from 'formik';
import { Box, useSnackbar } from 'pouncejs';

import SubmitButton from 'Components/submit-button';
import { GET_ORGANIZATION } from 'Pages/general-settings';
import FormikTextInput from 'Components/fields/text-input';
import { extractErrorMessage } from 'Helpers/utils';
import { UpdateOrganizationInput } from 'Generated/schema';

export const UPDATE_ORGANIZATION = gql`
  mutation UpdateCompanyInformation($input: UpdateOrganizationInput!) {
    updateOrganization(input: $input)
  }
`;

interface UpdateCompanyInformationFormValues {
  displayName?: string;
  email?: string;
}

interface ApolloMutationInput {
  input: UpdateOrganizationInput;
}

type UpdateCompanyInformationFormOuterProps = UpdateCompanyInformationFormValues & {
  onSuccess: () => void;
};

export const UpdateCompanyInformationForm: React.FC<UpdateCompanyInformationFormOuterProps> = ({
  displayName,
  email,
  onSuccess,
}) => {
  const { pushSnackbar } = useSnackbar();
  const [
    updateOrganization,
    { loading: updateOrganizationLoading, error: updateOrganizationError, data },
  ] = useMutation<boolean, ApolloMutationInput>(UPDATE_ORGANIZATION);

  React.useEffect(() => {
    if (updateOrganizationError) {
      pushSnackbar({
        variant: 'error',
        title:
          extractErrorMessage(updateOrganizationError) ||
          'Failed to update company information due to an unknown error',
      });
    }
  }, [updateOrganizationError]);

  React.useEffect(() => {
    if (data) {
      pushSnackbar({ variant: 'success', title: `Successfully updated company information` });
      onSuccess();
    }
  }, [data]);

  return (
    <Formik<UpdateCompanyInformationFormValues>
      initialValues={{
        displayName,
        email,
      }}
      onSubmit={async values => {
        await updateOrganization({
          variables: { input: values },
          refetchQueries: [{ query: GET_ORGANIZATION }],
        });
      }}
    >
      {({ handleSubmit }) => (
        <Box>
          <form onSubmit={handleSubmit}>
            <Box mb={8}>
              <Field as={FormikTextInput} name="displayName" label="Name" aria-required />
              <Field as={FormikTextInput} name="email" label="Email" aria-required />
            </Box>
            <SubmitButton
              disabled={updateOrganizationLoading}
              submitting={updateOrganizationLoading}
            >
              Update
            </SubmitButton>
          </form>
        </Box>
      )}
    </Formik>
  );
};

export default UpdateCompanyInformationForm;
