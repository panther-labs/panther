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
import { Flex, FormError, Text, AbstractButton, Link } from 'pouncejs';
import { useFormikContext } from 'formik';
import { copyTextToClipboard } from 'Helpers/utils';
import { Link as RRLink } from 'react-router-dom';
import urls from 'Source/urls';
import { WizardPanelWrapper } from 'Components/Wizard';
import { SqsLogSourceWizardValues } from '../SqsSourceWizard';

const InformationPanel: React.FC = () => {
  const { initialValues, setStatus, status } = useFormikContext<SqsLogSourceWizardValues>();

  // Reset error when the users navigate away from this stpe (so that when they come back, the
  // previous error isn't presented at them)
  React.useEffect(() => {
    return () => setStatus({ ...status, errorMessage: null });
  }, []);

  return (
    <Flex justify="center" align="center" direction="column" my={190} mx="auto" width={400}>
      <WizardPanelWrapper.Heading
        title="We created a SQS queue for you"
        subtitle="You need to send events on this queue url for Panther to process them"
      />
      <Text fontSize="small" mb={4}>
        {initialValues.queueUrl}
      </Text>
      <Text color="gray-300" mb={10}>
        You can copy the above URL or click{' '}
        <AbstractButton
          color="blue-400"
          onClick={() => copyTextToClipboard(initialValues.queueUrl)}
        >
          here
        </AbstractButton>{' '}
        to copy on clipboard
      </Text>
      <Text color="gray-300" mb={4}>
        Click Next if you want to edit your SQS source configuration or click{' '}
        <Link mr={1} as={RRLink} to={urls.logAnalysis.sources.list()}>
          here
        </Link>
        to return on Sources page
      </Text>
      {status.errorMessage && <FormError mt={6}>{status.errorMessage}</FormError>}
    </Flex>
  );
};

export default InformationPanel;
