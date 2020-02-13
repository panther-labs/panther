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
import { Alert, Box } from 'pouncejs';
import { useQuery, gql } from '@apollo/client';
import { ADMIN_ROLES_ARRAY } from 'Source/constants';
import { Organization } from 'Generated/schema';
import CompanyInformation from 'Pages/general-settings/subcomponent/company-information-panel';
import RoleRestrictedAccess from 'Components/role-restricted-access';
import Page404 from 'Pages/404';
import ErrorBoundary from 'Components/error-boundary';
import { extractErrorMessage } from 'Helpers/utils';
import GeneralSettingsPageSkeleton from './skeleton';

export const GET_ORGANIZATION = gql`
  query GetOrganization {
    organization {
      id
      displayName
      email
      alertReportFrequency
    }
  }
`;

interface ApolloQueryData {
  organization: Organization;
}

// Parent container for the general settings section
const GeneralSettingsContainer: React.FC = () => {
  // We're going to fetch the organization info at the top level and pass down relevant attributes and loading for each panel
  const { loading, error, data } = useQuery<ApolloQueryData>(GET_ORGANIZATION, {
    fetchPolicy: 'cache-and-network',
  });

  if (loading) {
    return <GeneralSettingsPageSkeleton />;
  }

  if (error) {
    return (
      <Alert
        variant="error"
        title="Failed to query company information"
        description={
          extractErrorMessage(error) ||
          'Sorry, something went wrong, please reach out to support@runpanther.io if this problem persists'
        }
      />
    );
  }

  return (
    <RoleRestrictedAccess allowedRoles={ADMIN_ROLES_ARRAY} fallback={<Page404 />}>
      <Box mb={6}>
        <ErrorBoundary>
          <CompanyInformation
            displayName={data.organization.displayName}
            email={data.organization.email}
          />
        </ErrorBoundary>
      </Box>
    </RoleRestrictedAccess>
  );
};

export default GeneralSettingsContainer;
