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
import { LIST_LOG_SOURCES } from 'Pages/list-sources/subcomponents/log-source-table';
import { AddIntegrationInput, Integration } from 'Generated/schema';
import { Formik } from 'formik';
import * as Yup from 'yup';
import useRouter from 'Hooks/useRouter';
import SourceDetailsPanel from './subcomponents/source-details-panel';
import CfnLaunchPanel from './subcomponents/cfn-launch-panel';
import SuccessPanel from './subcomponents/success-panel';
import PanelWrapper from '../panel-wrapper';

const ADD_LOG_SOURCE = gql`
  mutation AddSource($input: AddIntegrationInput!) {
    addIntegration(input: $input) {
      integrationId
    }
  }
`;

export interface CreateLogSourceValues {
  integrationLabel: string;
  awsAccountId: string;
  s3Buckets: string[];
  kmsKeys: string[];
}

const initialValues = {
  integrationLabel: '',
  awsAccountId: '',
  s3Buckets: [],
  kmsKeys: [],
};

const validationSchema = Yup.object().shape({
  integrationLabel: Yup.string().required(),
  awsAccountId: Yup.string()
    .matches(AWS_ACCOUNT_ID_REGEX, 'Must be a valid AWS Account ID')
    .required(),
  s3Buckets: Yup.array()
    .of(Yup.string())
    .required(),
  kmsKeys: Yup.array().of(Yup.string()),
});

interface ApolloMutationInput {
  input: AddIntegrationInput;
}

const CreateLogSource: React.FC = () => {
  const { history } = useRouter();
  const [addLogSource, { data, loading, error }] = useMutation<Integration, ApolloMutationInput>(
    ADD_LOG_SOURCE
  );

  const submitSourceToServer = React.useCallback(
    (values: CreateLogSourceValues) =>
      addLogSource({
        awaitRefetchQueries: true,
        variables: {
          input: {
            integrations: [
              {
                ...values,
                integrationType: INTEGRATION_TYPES.AWS_LOGS,
              },
            ],
          },
        },
        refetchQueries: [{ query: LIST_LOG_SOURCES }],
      }),
    []
  );

  React.useEffect(() => {
    if (data) {
      history.push(urls.logAnalysis.sources.list());
    }
  });

  return (
    <Box>
      {error && (
        <Alert
          variant="error"
          title="An error has occurred"
          description={
            extractErrorMessage(error) || "We couldn't store your source due to an internal error"
          }
          mb={6}
        />
      )}
      <Card p={9}>
        <Formik<CreateLogSourceValues>
          initialValues={initialValues}
          validationSchema={validationSchema}
          onSubmit={submitSourceToServer}
        >
          {({ errors, dirty, isValid, handleSubmit }) => (
            <form onSubmit={handleSubmit}>
              <Flex justifyContent="center" alignItems="center" width={1}>
                <Wizard<CreateLogSourceValues>
                  autoCompleteLastStep
                  steps={[
                    {
                      title: 'Setup your sources',
                      icon: 'search' as const,
                      renderStep: ({ goToNextStep }) => {
                        const shouldEnableNextButton =
                          dirty && !errors.integrationLabel && !errors.s3Buckets && !errors.kmsKeys;

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
                      title: 'Setup IAM Roles',
                      icon: 'upload',
                      renderStep: ({ goToPrevStep, goToNextStep }) => {
                        const shouldEnableNextButton = dirty && isValid;
                        return (
                          <PanelWrapper>
                            <PanelWrapper.Content>
                              <CfnLaunchPanel />
                            </PanelWrapper.Content>
                            <PanelWrapper.WizardActions
                              goToPrevStep={goToPrevStep}
                              goToNextStep={goToNextStep}
                              isNextStepDisabled={!shouldEnableNextButton}
                            />
                          </PanelWrapper>
                        );
                      },
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

export default CreateLogSource;
