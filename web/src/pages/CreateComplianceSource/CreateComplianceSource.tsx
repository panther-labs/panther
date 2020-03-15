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

/* eslint-disable react/display-name */
import React from 'react';
import { Card, Flex, Alert, Box } from 'pouncejs';
import { INTEGRATION_TYPES, AWS_ACCOUNT_ID_REGEX } from 'Source/constants';
import urls from 'Source/urls';
import { extractErrorMessage } from 'Helpers/utils';
import { ListInfraSourcesDocument } from 'Pages/ListComplianceSources';
import useRouter from 'Hooks/useRouter';
import { Formik } from 'formik';
import * as Yup from 'yup';
import { Wizard, WizardPanelWrapper } from 'Components/Wizard';
import { useAddInfraSource } from './graphql/addInfraSource.generated';
import StackDeploymentPanel from './StackDeploymentPanel';
import SuccessPanel from './SuccessPanel';
import SourceConfigurationPanel from './SourceConfigurationPanel';

export interface CreateInfraSourceValues {
  awsAccountId: string;
  integrationLabel: string;
  cweEnabled: boolean;
  remediationEnabled: boolean;
}

const validationSchema = Yup.object().shape<CreateInfraSourceValues>({
  integrationLabel: Yup.string().required(),
  awsAccountId: Yup.string()
    .matches(AWS_ACCOUNT_ID_REGEX, 'Must be a valid AWS Account ID')
    .required(),
  cweEnabled: Yup.boolean().required(),
  remediationEnabled: Yup.boolean().required(),
});

const initialValues = {
  awsAccountId: '',
  integrationLabel: '',
  cweEnabled: true,
  remediationEnabled: true,
};

const CreateComplianceSource: React.FC = () => {
  const { history } = useRouter();
  const [addInfraSource, { error }] = useAddInfraSource({
    onCompleted: () => history.push(urls.compliance.sources.list()),
    refetchQueries: [{ query: ListInfraSourcesDocument }],
    awaitRefetchQueries: true,
  });

  const submitSourceToServer = React.useCallback(
    (values: CreateInfraSourceValues) =>
      addInfraSource({
        variables: {
          input: {
            integrations: [
              {
                awsAccountId: values.awsAccountId,
                integrationLabel: values.integrationLabel,
                integrationType: INTEGRATION_TYPES.AWS_INFRA,
              },
            ],
          },
        },
      }),
    []
  );

  return (
    <Box>
      {error && (
        <Alert
          variant="error"
          title="An error has occurred"
          description={
            extractErrorMessage(error) || "We couldn't store your account due to an internal error"
          }
          mb={6}
        />
      )}
      <Card p={9}>
        <Formik<CreateInfraSourceValues>
          initialValues={initialValues}
          initialStatus={{ cfnTemplateDownloaded: false }}
          validationSchema={validationSchema}
          onSubmit={submitSourceToServer}
        >
          {({ isValid, dirty, handleSubmit, status }) => {
            const shouldEnableNextButton = dirty && isValid;

            return (
              <form onSubmit={handleSubmit}>
                <Flex justifyContent="center" alignItems="center" width={1}>
                  <Wizard>
                    <Wizard.Step title="Configure Sourcee" icon="settings">
                      <WizardPanelWrapper>
                        <WizardPanelWrapper.Content>
                          <SourceConfigurationPanel />
                        </WizardPanelWrapper.Content>
                        <WizardPanelWrapper.Actions>
                          <WizardPanelWrapper.ActionNext disabled={!shouldEnableNextButton} />
                        </WizardPanelWrapper.Actions>
                      </WizardPanelWrapper>
                    </Wizard.Step>
                    <Wizard.Step title="Deploy Stack" icon="upload">
                      <WizardPanelWrapper>
                        <WizardPanelWrapper.Content>
                          <StackDeploymentPanel />
                        </WizardPanelWrapper.Content>
                        <WizardPanelWrapper.Actions>
                          <WizardPanelWrapper.ActionPrev />
                          <WizardPanelWrapper.ActionNext disabled={!status.cfnTemplateDownloaded} />
                        </WizardPanelWrapper.Actions>
                      </WizardPanelWrapper>
                    </Wizard.Step>
                    <Wizard.Step title="Done!" icon="check">
                      <WizardPanelWrapper>
                        <WizardPanelWrapper.Content>
                          <SuccessPanel />
                        </WizardPanelWrapper.Content>
                        <WizardPanelWrapper.Actions>
                          <WizardPanelWrapper.ActionPrev />
                        </WizardPanelWrapper.Actions>
                      </WizardPanelWrapper>
                    </Wizard.Step>
                  </Wizard>
                </Flex>
              </form>
            );
          }}
        </Formik>
      </Card>
    </Box>
  );
};

export default CreateComplianceSource;
