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
import { Flex, Alert, Link, Spinner } from 'pouncejs';
import { useFormikContext } from 'formik';
import { extractErrorMessage } from 'Helpers/utils';
import { REMEDIATION_DOC_URL } from 'Source/constants';
import { PolicyFormValues } from '../PolicyForm';
import { useListRemediations } from './graphql/listRemediations.generated';
import PolicyFormAutoRemediationFields, {
  PolicyFormAutoRemediationFieldsProps,
} from './PolicyFormAutoRemediationFields';

const PolicyFormAutoRemediationSection: React.FC = () => {
  // Read the values from the "parent" form. We expect a formik to be declared in the upper scope
  // since this is a "partial" form. If no Formik context is found this will error out intentionally
  const { setFieldValue, initialValues } = useFormikContext<PolicyFormValues>();

  const { data, loading, error } = useListRemediations();

  const handleAutoRemediationFieldChange: PolicyFormAutoRemediationFieldsProps['onChange'] = React.useCallback(
    ({ autoRemediationId, autoRemediationParameters }) => {
      setFieldValue('autoRemediationId', autoRemediationId);
      setFieldValue('autoRemediationParameters', autoRemediationParameters);
    },
    [setFieldValue]
  );

  if (loading) {
    return (
      <Flex w="100%" justify="center" my={10}>
        <Spinner />
      </Flex>
    );
  }

  if (error) {
    return (
      <Alert
        variant="warning"
        title="Couldn't load your available remediations"
        description={[
          extractErrorMessage(error),
          '. For more info, please consult the ',
          <Link external href={REMEDIATION_DOC_URL} key="docs">
            related docs
          </Link>,
        ]}
      />
    );
  }
  return (
    <PolicyFormAutoRemediationFields
      initialValues={initialValues}
      remediations={data.remediations}
      onChange={handleAutoRemediationFieldChange}
    />
  );
};

export default React.memo(PolicyFormAutoRemediationSection);
