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
import { Alert, Box, useSnackbar } from 'pouncejs';
import { useQuery, gql, useMutation } from '@apollo/client';
import { ADMIN_ROLES_ARRAY } from 'Source/constants';
import { Organization, UpdateOrganizationInput } from 'Generated/schema';
import Panel from 'Components/panel';
import RoleRestrictedAccess from 'Components/role-restricted-access';
import Page404 from 'Pages/404';
import ErrorBoundary from 'Components/error-boundary';
import { extractErrorMessage } from 'Helpers/utils';
import GeneralSettingsPageSkeleton from './skeleton';
import CompanyInformationForm from './subcomponents/company-information-form';

export const GET_ORGANIZATION = gql`
  query GetOrganization {
    organization {
      id
      displayName
      email
      errorReportingConsent
    }
  }
`;

const UPDATE_ORGANIZATION = gql`
  mutation UpdateCompanyInformation($input: UpdateOrganizationInput!) {
    updateOrganization(input: $input) {
      id
      displayName
      email
      errorReportingConsent
    }
  }
`;

interface ApolloMutationInput {
  input: UpdateOrganizationInput;
}

interface ApolloMutationData {
  updateOrganization: Pick<Organization, 'id' | 'displayName' | 'email' | 'errorReportingConsent'>;
}

interface ApolloQueryData {
  organization: Organization;
}

// Parent container for the general settings section
const GeneralSettingsContainer: React.FC = () => {
  const { pushSnackbar } = useSnackbar();

  const {
    loading: getOrganizationLoading,
    error: getOrganizationError,
    data: getOrganizationData,
  } = useQuery<ApolloQueryData>(GET_ORGANIZATION, {
    fetchPolicy: 'cache-and-network',
  });

  const [
    updateOrganization,
    { error: updateOrganizationError, data: updateOrganizationData },
  ] = useMutation<ApolloMutationData, ApolloMutationInput>(UPDATE_ORGANIZATION);

  React.useEffect(() => {
    if (updateOrganizationData) {
      pushSnackbar({ variant: 'success', title: `Successfully updated company information` });
    }
  }, [updateOrganizationData]);

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

  if (getOrganizationLoading) {
    return <GeneralSettingsPageSkeleton />;
  }

  if (getOrganizationError) {
    return (
      <Alert
        variant="error"
        title="Failed to query company information"
        description={
          extractErrorMessage(getOrganizationError) ||
          'Sorry, something went wrong, please reach out to support@runpanther.io if this problem persists'
        }
      />
    );
  }

  const { displayName, email, errorReportingConsent } = getOrganizationData.organization;
  return (
    <RoleRestrictedAccess allowedRoles={ADMIN_ROLES_ARRAY} fallback={<Page404 />}>
      <Box mb={6}>
        <ErrorBoundary>
          <Panel size="large" title="Company Information">
            <CompanyInformationForm
              initialValues={{
                displayName,
                email,
                errorReportingConsent,
              }}
              onSubmit={values => updateOrganization({ variables: { input: values } })}
            />
          </Panel>
        </ErrorBoundary>
      </Box>
    </RoleRestrictedAccess>
  );
};

export default GeneralSettingsContainer;
