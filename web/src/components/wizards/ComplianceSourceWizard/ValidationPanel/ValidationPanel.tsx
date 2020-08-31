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
import { AbstractButton, Button, Flex, Img, Link } from 'pouncejs';
import { useFormikContext } from 'formik';
import FailureStatus from 'Assets/statuses/failure.svg';
import WaitingStatus from 'Assets/statuses/waiting.svg';
import SuccessStatus from 'Assets/statuses/success.svg';
import { Link as RRLink } from 'react-router-dom';
import urls from 'Source/urls';
import { useWizardContext, WizardPanel } from 'Components/Wizard';
import { extractErrorMessage } from 'Helpers/utils';
import { ApolloError } from '@apollo/client';
import { ComplianceSourceWizardValues } from '../ComplianceSourceWizard';

const ValidationPanel: React.FC = () => {
  const [errorMessage, setErrorMessage] = React.useState('');
  const { goToPrevStep, reset, currentStepStatus, setCurrentStepStatus } = useWizardContext();
  const { initialValues, submitForm } = useFormikContext<ComplianceSourceWizardValues>();

  React.useEffect(() => {
    (async () => {
      try {
        await submitForm();
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
        <Flex align="center" direction="column" mx="auto" width={350}>
          <WizardPanel.Heading
            title="Everything looks good!"
            subtitle={
              initialValues.integrationId
                ? 'Your stack was successfully updated'
                : 'Your configured stack was deployed successfully and your source’s setup is now complete!'
            }
          />
          <Img
            nativeWidth={120}
            nativeHeight={120}
            alt="Stack deployed successfully"
            src={SuccessStatus}
          />
          <WizardPanel.Actions>
            <Flex direction="column" spacing={4}>
              <RRLink to={urls.compliance.sources.list()}>
                <Button as="div" onClick={goToPrevStep}>
                  Finish Setup
                </Button>
              </RRLink>
              {!initialValues.integrationId && (
                <Link as={AbstractButton} variant="discreet" onClick={reset}>
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
            <Button onClick={reset}>Start over</Button>
          </WizardPanel.Actions>
        </Flex>
      </WizardPanel>
    );
  }

  return (
    <WizardPanel>
      <Flex align="center" direction="column" mx="auto">
        <WizardPanel.Heading
          title="Almost There!"
          subtitle="We are just making sure that everything is setup correctly. Hold on tight..."
        />
        <Img
          nativeWidth={120}
          nativeHeight={120}
          alt="Validating source health..."
          src={WaitingStatus}
        />
        <WizardPanel.Actions>
          <Button variantColor="darkgray" onClick={goToPrevStep}>
            Cancel
          </Button>
        </WizardPanel.Actions>
      </Flex>
    </WizardPanel>
  );
};

export default ValidationPanel;
