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
import { Flex, FormError, Heading, Text } from 'pouncejs';
import { useFormikContext } from 'formik';
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
      <Heading as="h2" m="auto" mb={5}>
        We created a SQS queue for you
      </Heading>
      <Text color="gray-300" mb={2}>
        You need to send events on this queue url for Panther to process them:
      </Text>
      <Text fontSize="small" mb={10}>
        {initialValues.queueUrl}
      </Text>
      <Text color="gray-300" mb={4}>
        Click Next if you want to edit your SQS source configuration
      </Text>
      {status.errorMessage && <FormError mt={6}>{status.errorMessage}</FormError>}
    </Flex>
  );
};

export default InformationPanel;
