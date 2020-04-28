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
import { Flex, Heading, Text } from 'pouncejs';
import SubmitButton from 'Components/buttons/SubmitButton';
import { useFormikContext } from 'formik';
import { ComplianceSourceWizardValues } from '../ComplianceSourceWizard';

interface SuccessPanelProps {
  errorMessage?: string;
}

const SuccessPanel: React.FC<SuccessPanelProps> = ({ errorMessage }) => {
  const { isSubmitting, initialValues, status, setStatus } = useFormikContext<
    ComplianceSourceWizardValues
  >();

  // Reset error when the users navigate away from this stpe (so that when they come back, the
  // previous error isn't presented at them)
  React.useEffect(() => {
    return () => setStatus({ ...status, errorMessage: null });
  }, []);

  return (
    <Flex justify="center" align="center" direction="column" my={190} mx="auto" width={350}>
      <Heading size="medium" m="auto" mb={5} color="grey400">
        Almost done!
      </Heading>
      <Text size="large" color="grey300" mb={10} textAlign="center">
        {initialValues.integrationId
          ? 'Click the button below to validate your changes & update your source!'
          : 'After deploying your Cloudformation stack, click on the button below to complete the setup!'}
      </Text>
      <SubmitButton width={350} disabled={isSubmitting} submitting={isSubmitting}>
        {initialValues.integrationId ? 'Update Source' : 'Save Source'}
      </SubmitButton>
      <Text size="large" mt={6} color="red300">
        {errorMessage}
      </Text>
    </Flex>
  );
};

export default SuccessPanel;
