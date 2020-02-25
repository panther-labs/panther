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
import Wizard from 'Components/wizard';
import urls from 'Source/urls';
import { extractErrorMessage } from 'Helpers/utils';
import { useMutation, gql } from '@apollo/client';
import { LIST_INFRA_SOURCES } from 'Pages/list-sources/subcomponents/infra-source-table';
import useRouter from 'Hooks/useRouter';
import { Formik } from 'formik';
import * as Yup from 'yup';
import { AddIntegrationInput, Integration } from 'Generated/schema';
import RemediationPanel from './subcomponents/remediation-panel';
import RealTimeEventPanel from './subcomponents/real-time-event-panel';
import ResourceScanningPanel from './subcomponents/resource-scanning-panel';
import SuccessPanel from './subcomponents/success-panel';
import PanelWrapper from '../panel-wrapper';
import SourceDetailsPanel from './subcomponents/source-details-panel';

const ADD_INFRA_SOURCE = gql`
  mutation AddInfraSource($input: AddIntegrationInput!) {
    addIntegration(input: $input) {
      integrationId
    }
  }
`;

export interface InfraSourceValues {
  awsAccountId: string;
  integrationLabel: string;
}

const validationSchema = Yup.object().shape({
  awsAccountId: Yup.string()
    .matches(AWS_ACCOUNT_ID_REGEX, 'Must be a valid AWS Account ID')
    .required(),
  integrationLabel: Yup.string().required(),
});

const initialValues = {
  awsAccountId: '',
  integrationLabel: '',
};

interface ApolloMutationInput {
  input: AddIntegrationInput;
}
const Index: React.FC = () => {
  const { history } = useRouter();
  const [addInfraSource, { data, loading, error }] = useMutation<Integration, ApolloMutationInput>(
    ADD_INFRA_SOURCE
  );

  const submitSourceToServer = React.useCallback(
    (values: InfraSourceValues) =>
      addInfraSource({
        awaitRefetchQueries: true,
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
        refetchQueries: [{ query: LIST_INFRA_SOURCES }],
      }),
    []
  );

  React.useEffect(() => {
    if (data) {
      history.push(urls.compliance.sources.list());
    }
  });

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
        <Formik<InfraSourceValues>
          initialValues={initialValues}
          validationSchema={validationSchema}
          onSubmit={submitSourceToServer}
        >
          {({ isValid, dirty, handleSubmit }) => (
            <form onSubmit={handleSubmit}>
              <Flex justifyContent="center" alignItems="center" width={1}>
                <Wizard<InfraSourceValues>
                  autoCompleteLastStep
                  steps={[
                    {
                      title: 'Account Details',
                      icon: 'add' as const,
                      renderStep: ({ goToNextStep }) => {
                        const shouldEnableNextButton = dirty && isValid;
                        return (
                          <PanelWrapper>
                            <PanelWrapper.Content>
                              <SourceDetailsPanel />
                            </PanelWrapper.Content>
                            <PanelWrapper.WizardActions
                              goToNextStep={goToNextStep}
                              isNextStepDisabled={!shouldEnableNextButton}
                            />
                          </PanelWrapper>
                        );
                      },
                    },
                    {
                      title: 'Scanning',
                      icon: 'search',
                      renderStep: ({ goToPrevStep, goToNextStep }) => (
                        <PanelWrapper>
                          <PanelWrapper.Content>
                            <ResourceScanningPanel />
                          </PanelWrapper.Content>
                          <PanelWrapper.WizardActions
                            goToNextStep={goToNextStep}
                            goToPrevStep={goToPrevStep}
                          />
                        </PanelWrapper>
                      ),
                    },
                    {
                      title: 'Real Time',
                      icon: 'sync',
                      renderStep: ({ goToPrevStep, goToNextStep }) => (
                        <PanelWrapper>
                          <PanelWrapper.Content>
                            <RealTimeEventPanel />
                          </PanelWrapper.Content>
                          <PanelWrapper.WizardActions
                            goToNextStep={goToNextStep}
                            goToPrevStep={goToPrevStep}
                          />
                        </PanelWrapper>
                      ),
                    },
                    {
                      title: 'Remediation',
                      icon: 'wrench',
                      renderStep: ({ goToPrevStep, goToNextStep }) => (
                        <PanelWrapper>
                          <PanelWrapper.Content>
                            <RemediationPanel />
                          </PanelWrapper.Content>
                          <PanelWrapper.WizardActions
                            goToNextStep={goToNextStep}
                            goToPrevStep={goToPrevStep}
                          />
                        </PanelWrapper>
                      ),
                    },
                    {
                      title: 'Done!',
                      icon: 'check',
                      renderStep: ({ goToPrevStep }) => (
                        <PanelWrapper>
                          <PanelWrapper.Content>
                            <SuccessPanel loading={loading} />
                          </PanelWrapper.Content>
                          <PanelWrapper.WizardActions goToPrevStep={goToPrevStep} />
                        </PanelWrapper>
                      ),
                    },
                  ]}
                />
              </Flex>
            </form>
          )}
        </Formik>
      </Card>
    </Box>
  );
};

export default Index;
