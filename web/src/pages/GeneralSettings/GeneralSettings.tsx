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
import { Alert, Box, useSnackbar, Flex, Card, SimpleGrid, Img } from 'pouncejs';
import ErrorBoundary from 'Components/ErrorBoundary';
import PantherIcon from 'Assets/panther-plain-logo.svg';
import { pantherConfig } from 'Source/config';
import { extractErrorMessage } from 'Helpers/utils';
import CompanyInformationForm from 'Components/forms/CompanyInformationForm';
import Footer from 'Components/Footer';
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

  const { displayName, email, errorReportingConsent, analyticsConsent } = getGeneralSettingsData.generalSettings; // prettier-ignore
  return (
    <>
      <Flex direction="column" minHeight="80%">
        <SimpleGrid columns={3} spacing={5}>
          <Box as="article">
            <Card px={6} py={9}>
              <ErrorBoundary>
                <CompanyInformationForm
                  initialValues={{
                    displayName,
                    email,
                    errorReportingConsent,
                    analyticsConsent,
                  }}
                  onSubmit={values => updateGeneralSettings({ variables: { input: values } })}
                />
              </ErrorBoundary>
            </Card>
          </Box>
        </SimpleGrid>
      </Flex>
      <Footer>
        <Flex spacing={170}>
          <Box>
            <Img
              src={PantherIcon}
              alt="Panther logo"
              nativeWidth={94}
              nativeHeight={20}
              mb={3}
              display="block"
            />
            <LinkButton
              external
              size="small"
              to="https://runpanther.io/pricing/"
              variantColor="navyblue"
              variant="outline"
            >
              Get Enterprise
            </LinkButton>
          </Box>
          <Flex as="dl" spacing={9} align="center">
            <Box as="section">
              <Box id="plan" as="dt" color="navyblue-100" fontSize="small" mb={1}>
                Plan
              </Box>
              <Box aria-labelledby="plan" as="dd" fontSize="medium">
                Community
              </Box>
            </Box>

            <Box as="section">
              <Box id="aws_account_id" as="dt" color="navyblue-100" fontSize="small" mb={1}>
                AWS Account ID
              </Box>
              <Box aria-labelledby="aws_account_id" as="dd" fontSize="medium">
                {pantherConfig.AWS_ACCOUNT_ID}
              </Box>
            </Box>
            <Box as="section">
              <Box id="panther_version" as="dt" color="navyblue-100" fontSize="small" mb={1}>
                Version
              </Box>
              <Box aria-labelledby="panther_version" as="dd" fontSize="medium">
                {pantherConfig.PANTHER_VERSION} ({pantherConfig.PANTHER_COMMIT})
              </Box>
            </Box>
            <Box as="section">
              <Box id="aws_region" as="dt" color="navyblue-100" fontSize="small" mb={1}>
                AWS Region
              </Box>
              <Box aria-labelledby="aws_region" as="dd" fontSize="medium">
                {pantherConfig.AWS_REGION}
              </Box>
            </Box>
          </Flex>
        </Flex>
      </Footer>
    </>
  );
};

export default withSEO({ title: 'General Settings' })(GeneralSettingsPage);
