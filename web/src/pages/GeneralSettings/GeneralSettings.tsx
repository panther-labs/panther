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
import { Alert, Box, useSnackbar, Flex, Heading, Card, SimpleGrid } from 'pouncejs';
import ErrorBoundary from 'Components/ErrorBoundary';
import { pantherConfig } from 'Source/config';
import { extractErrorMessage } from 'Helpers/utils';
import CompanyInformationForm from 'Components/forms/CompanyInformationForm';
import LinkButton from 'Components/buttons/LinkButton';
import withSEO from 'Hoc/withSEO';
import { useGetGeneralSettings } from './graphql/getGeneralSettings.generated';
import { useUpdateGeneralSettings } from './graphql/updateGeneralSettings.generated';
import GeneralSettingsPageSkeleton from './Skeleton';

// Parent container for the general settings section
const GeneralSettingsPage: React.FC = () => {
  const { pushSnackbar } = useSnackbar();

  const {
    loading: getGeneralSettingsLoading,
    error: getGeneralSettingsError,
    data: getGeneralSettingsData,
  } = useGetGeneralSettings();

  const [updateGeneralSettings] = useUpdateGeneralSettings({
    onCompleted: () => {
      pushSnackbar({ variant: 'success', title: `Successfully updated company information` });
    },
    onError: error => {
      pushSnackbar({
        variant: 'error',
        title:
          extractErrorMessage(error) ||
          'Failed to update company information due to an unknown error',
      });
    },
  });

  if (getGeneralSettingsLoading) {
    return <GeneralSettingsPageSkeleton />;
  }

  if (getGeneralSettingsError) {
    return (
      <Alert
        variant="error"
        title="Failed to query company information"
        description={
          extractErrorMessage(getGeneralSettingsError) ||
          'Sorry, something went wrong, please reach out to support@runpanther.io if this problem persists'
        }
      />
    );
  }

  const { displayName, email, errorReportingConsent } = getGeneralSettingsData.generalSettings;
  return (
    <SimpleGrid columns={3} spacing={5}>
      <Box as="article">
        <Card px={6} py={9}>
          <ErrorBoundary>
            <CompanyInformationForm
              initialValues={{
                displayName,
                email,
                errorReportingConsent,
              }}
              onSubmit={values => updateGeneralSettings({ variables: { input: values } })}
            />
          </ErrorBoundary>
        </Card>
      </Box>
      <Box as="article">
        <Card p={6}>
          <Flex direction="column" spacing={6}>
            <Heading as="h2" size="x-small" mt={2}>
              About Panther
            </Heading>
            <Flex as="section" align="center" justify="space-between">
              <Box>
                <Box color="navyblue-100" fontSize="small" mb={1}>
                  Plan
                </Box>
                <Box fontWeight="medium">Community</Box>
              </Box>
              <LinkButton
                external
                to="https://runpanther.io/pricing/"
                variantColor="navyblue"
                variant="outline"
              >
                Change
              </LinkButton>
            </Flex>
            <Box as="section">
              <Box color="navyblue-100" fontSize="small" mb={1}>
                Version
              </Box>
              <Box fontWeight="medium">{pantherConfig.PANTHER_VERSION || 'N/A'}</Box>
            </Box>
            <Box as="section">
              <Box color="navyblue-100" fontSize="small" mb={1}>
                AWS Account ID
              </Box>
              <Box fontWeight="medium">{pantherConfig.AWS_ACCOUNT_ID}</Box>
            </Box>
            <Box as="section">
              <Box color="navyblue-100" fontSize="small" mb={1}>
                AWS Region
              </Box>
              <Box fontWeight="medium">{pantherConfig.AWS_REGION}</Box>
            </Box>
          </Flex>
        </Card>
      </Box>
    </SimpleGrid>
  );
};

export default withSEO({ title: 'General Settings' })(GeneralSettingsPage);
