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
import { AbstractButton, Button, Flex, Img, Link, useSnackbar } from 'pouncejs';
import { useFormikContext } from 'formik';
import FailureStatus from 'Assets/statuses/failure.svg';
import WaitingStatus from 'Assets/statuses/waiting.svg';
import SuccessStatus from 'Assets/statuses/success.svg';
import urls from 'Source/urls';
import { useWizardContext, WizardPanel } from 'Components/Wizard';
import { copyTextToClipboard, extractErrorMessage } from 'Helpers/utils';
import { ApolloError } from '@apollo/client';
import LinkButton from 'Components/buttons/LinkButton';
import { AddSqsLogSourceMutationResult } from 'Pages/CreateLogSource/CreateSqsLogSource/graphql/addSqsLogSource.generated';
import { UpdateSqsLogSourceMutationResult } from 'Pages/EditSqsLogSource/graphql/updateSqsLogSource.generated';
import { SqsLogSourceWizardValues } from '../SqsSourceWizard';

const ValidationPanel: React.FC = () => {
  const { pushSnackbar } = useSnackbar();
  const [errorMessage, setErrorMessage] = React.useState('');
  const result = React.useRef<AddSqsLogSourceMutationResult | UpdateSqsLogSourceMutationResult>(null); // prettier-ignore
  const { reset: resetWizard, currentStepStatus, setCurrentStepStatus } = useWizardContext(); // prettier-ignore
  const { initialValues, submitForm, resetForm } = useFormikContext<SqsLogSourceWizardValues>();

  React.useEffect(() => {
    (async () => {
      try {
        result.current = await (submitForm() as Promise<any>);
        setErrorMessage('');
        setCurrentStepStatus('PASSING');
      } catch (err) {
        setErrorMessage(extractErrorMessage(err as ApolloError));
        setCurrentStepStatus('FAILING');
      }
    })();
  }, []);

  if (currentStepStatus === 'PASSING') {
    return (
      <WizardPanel>
        <Flex align="center" direction="column" mx="auto" width={400}>
          <WizardPanel.Heading
            title={
              initialValues.integrationId
                ? 'Everything looks good!'
                : 'An SQS Queue has been created for you!'
            }
            subtitle={
              initialValues.integrationId
                ? 'Your SQS source was successfully updated'
                : 'Panther will now automatically process any events you send to this queue'
            }
          />
          <Img
            nativeWidth={120}
            nativeHeight={120}
            alt="Stack deployed successfully"
            src={SuccessStatus}
          />
          <AbstractButton
            mt={6}
            p={1}
            color="blue-200"
            fontSize="medium"
            _hover={{ color: 'blue-100' }}
            onClick={() => {
              copyTextToClipboard(
                initialValues.integrationId
                  ? (result.current as UpdateSqsLogSourceMutationResult).data.updateSqsLogIntegration.sqsConfig.queueUrl // prettier-ignore
                  : (result.current as AddSqsLogSourceMutationResult).data.addSqsLogIntegration.sqsConfig.queueUrl // prettier-ignore
              );
              pushSnackbar({ variant: 'default', title: 'Copied to clipboard', duration: 2000 });
            }}
          >
            Copy SQS Queue URL
          </AbstractButton>
          <WizardPanel.Actions>
            <Flex direction="column" spacing={4}>
              <LinkButton to={urls.integrations.logSources.list()}>Finish Setup</LinkButton>
              {!initialValues.integrationId && (
                <Link
                  as={AbstractButton}
                  variant="discreet"
                  onClick={() => {
                    resetForm();
                    resetWizard();
                  }}
                >
                  Add Another
                </Link>
              )}
            </Flex>
          </WizardPanel.Actions>
        </Flex>
      </WizardPanel>
    );
  }

  if (currentStepStatus === 'FAILING') {
    return (
      <WizardPanel>
        <Flex align="center" direction="column" mx="auto">
          <WizardPanel.Heading title="Something didn't go as planned" subtitle={errorMessage} />
          <Img
            nativeWidth={120}
            nativeHeight={120}
            alt="Failed to verify source health"
            src={FailureStatus}
          />
          <WizardPanel.Actions>
            <Button onClick={resetWizard}>Start over</Button>
          </WizardPanel.Actions>
        </Flex>
      </WizardPanel>
    );
  }

  return (
    <WizardPanel>
      <Flex align="center" direction="column" mx="auto">
        <WizardPanel.Heading
          title={initialValues.integrationId ? 'Updating your SQS queue' : 'Creating an SQS queue'}
          subtitle={
            initialValues.integrationId
              ? 'Hold on tight...'
              : 'We are generating a queue for you to push messages to. Hold on tight...'
          }
        />
        <Img
          nativeWidth={120}
          nativeHeight={120}
          alt="Validating source health..."
          src={WaitingStatus}
        />
      </Flex>
    </WizardPanel>
  );
};

export default ValidationPanel;
