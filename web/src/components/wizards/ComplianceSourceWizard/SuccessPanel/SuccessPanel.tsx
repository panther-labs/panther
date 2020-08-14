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
import { Flex, FormError } from 'pouncejs';
import SubmitButton from 'Components/buttons/SubmitButton';
import { useFormikContext } from 'formik';
import { WizardPanelWrapper } from 'Components/Wizard';
import { ComplianceSourceWizardValues } from '../ComplianceSourceWizard';

const SuccessPanel: React.FC = () => {
  const { initialValues, status, setStatus } = useFormikContext<ComplianceSourceWizardValues>();

  // Reset error when the users navigate away from this stpe (so that when they come back, the
  // previous error isn't presented at them)
  React.useEffect(() => {
    return () => setStatus({ ...status, errorMessage: null });
  }, []);

  return (
    <Flex justify="center" align="center" direction="column" mx="auto" width={400}>
      <WizardPanelWrapper.Heading
        title="Almost Done!"
        subtitle={
          initialValues.integrationId
            ? 'Click the button below to validate your changes & update your source!'
            : 'After deploying your Cloudformation stack, click on the button below to complete the setup!'
        }
      />
      <SubmitButton fullWidth>
        {initialValues.integrationId ? 'Update Source' : 'Save Source'}
      </SubmitButton>
      {status.errorMessage && <FormError mt={6}>{status.errorMessage}</FormError>}
    </Flex>
  );
};

export default SuccessPanel;
