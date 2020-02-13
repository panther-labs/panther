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

import React from 'react';
import { Modal, Text, Box, useSnackbar, Alert } from 'pouncejs';
import { gql, useMutation, useQuery } from '@apollo/client';
import useModal from 'Hooks/useModal';
import AnalyticsConsentForm from 'Components/forms/analytics-consent-form';
import { extractErrorMessage } from 'Helpers/utils';
import { Organization, UpdateOrganizationInput } from 'Generated/schema';

const UPDATE_ORGANIZATION = gql`
  mutation UpdateCompanyDetails($input: UpdateOrganizationInput!) {
    updateOrganization(input: $input) {
      id
      errorReportingConsent
    }
  }
`;

const GET_ORGANIZATION = gql`
  query GetOrganizationDetails {
    organization {
      id
      displayName
      email
    }
  }
`;

interface ApolloMutationInput {
  input: Pick<UpdateOrganizationInput, 'errorReportingConsent' | 'displayName' | 'email'>;
}

interface ApolloMutationData {
  updateOrganization: Pick<Organization, 'id' | 'errorReportingConsent' | 'displayName' | 'email'>;
}

interface ApolloQueryData {
  organization: Organization;
}

const AnalyticsConsentModal: React.FC = () => {
  const { pushSnackbar } = useSnackbar();
  const { hideModal } = useModal();
  const [saveConsentPreferences, { data: updateOrganizationData, error }] = useMutation<
    ApolloMutationData,
    ApolloMutationInput
  >(UPDATE_ORGANIZATION);
  const { data: getOrganizationData } = useQuery<ApolloQueryData>(GET_ORGANIZATION);

  React.useEffect(() => {
    if (updateOrganizationData) {
      pushSnackbar({ variant: 'success', title: `Successfully updated your preferences` });
      hideModal();
    }
  }, [updateOrganizationData]);

  return (
    <Modal
      open
      disableBackdropClick
      disableEscapeKeyDown
      onClose={hideModal}
      title="Help us make Panther better"
    >
      <Box width={600} px={100} py={25}>
        <Text size="large" color="grey300" mb={8} textAlign="center">
          Which data can the Panther team receive from you?
        </Text>
        {error ? (
          <Alert
            title="An error occured"
            description={extractErrorMessage(error)}
            variant="error"
          />
        ) : (
          <AnalyticsConsentForm
            onSubmit={values =>
              saveConsentPreferences({
                variables: {
                  input: {
                    displayName: getOrganizationData.organization.displayName,
                    email: getOrganizationData.organization.email,
                    ...values,
                  },
                },
              })
            }
          />
        )}
      </Box>
    </Modal>
  );
};

export default AnalyticsConsentModal;
