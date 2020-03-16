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
import { AWS_ACCOUNT_ID_REGEX } from 'Source/constants';
import urls from 'Source/urls';
import { extractErrorMessage } from 'Helpers/utils';
import { Formik } from 'formik';
import * as Yup from 'yup';
import { Wizard, WizardPanelWrapper } from 'Components/Wizard';
import useRouter from 'Hooks/useRouter';
import { ListLogSourcesDocument } from 'Pages/ListLogSources';
import SourceDetailsPanel from './SourceDetailsPanel';
import CfnLaunchPanel from './CfnLaunchPanel';
import SuccessPanel from './SuccessPanel';
import { useAddLogSource } from './graphql/addLogSource.generated';

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

const CreateLogSource: React.FC = () => {
  const { history } = useRouter();
  const [addLogSource, { error }] = useAddLogSource({
    refetchQueries: [{ query: ListLogSourcesDocument }],
    awaitRefetchQueries: true,
    onCompleted: () => history.push(urls.logAnalysis.sources.list()),
  });

  const submitSourceToServer = React.useCallback(
    (values: CreateLogSourceValues) =>
      addLogSource({
        variables: {
          input: values,
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
          {({ dirty, isValid, handleSubmit }) => {
            const shouldEnableNextButton = dirty && isValid;

            return (
              <form onSubmit={handleSubmit}>
                <Flex justifyContent="center" alignItems="center" width={1}>
                  <Wizard>
                    <Wizard.Step title="Setup your sources" icon="search">
                      <WizardPanelWrapper>
                        <WizardPanelWrapper.Content>
                          <SourceDetailsPanel />
                        </WizardPanelWrapper.Content>
                        <WizardPanelWrapper.Actions>
                          <WizardPanelWrapper.ActionNext disabled={!shouldEnableNextButton} />
                        </WizardPanelWrapper.Actions>
                      </WizardPanelWrapper>
                    </Wizard.Step>
                    <Wizard.Step title="Setup IAM Roles" icon="upload">
                      <WizardPanelWrapper>
                        <WizardPanelWrapper.Content>
                          <CfnLaunchPanel />
                        </WizardPanelWrapper.Content>
                        <WizardPanelWrapper.Actions>
                          <WizardPanelWrapper.ActionPrev />
                          <WizardPanelWrapper.ActionNext disabled={!shouldEnableNextButton} />
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

export default CreateLogSource;
