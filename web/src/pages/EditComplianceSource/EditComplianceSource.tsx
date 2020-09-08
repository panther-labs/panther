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
import { useSnackbar } from 'pouncejs';
import Page404 from 'Pages/404';
import useRouter from 'Hooks/useRouter';
import withSEO from 'Hoc/withSEO';
import { extractErrorMessage } from 'Helpers/utils';
import ComplianceSourceWizard from 'Components/wizards/ComplianceSourceWizard';
import { useGetComplianceSource } from './graphql/getComplianceSource.generated';
import { useUpdateComplianceSource } from './graphql/updateComplianceSource.generated';

const EditComplianceSource: React.FC = () => {
  const { pushSnackbar } = useSnackbar();
  const { match } = useRouter<{ id: string }>();

  const { data, error: getError } = useGetComplianceSource({
    variables: { id: match.params.id },
    onError: error => {
      pushSnackbar({
        title: extractErrorMessage(error) || 'An unknown error occurred',
        variant: 'error',
      });
    },
  });

  const [updateComplianceSource] = useUpdateComplianceSource();

  const initialValues = React.useMemo(
    () => ({
      integrationId: data?.getComplianceIntegration.integrationId,
      integrationLabel: data?.getComplianceIntegration.integrationLabel ?? 'Loading...',
      awsAccountId: data?.getComplianceIntegration.awsAccountId ?? 'Loading...',
      cweEnabled: data?.getComplianceIntegration.cweEnabled ?? false,
      remediationEnabled: data?.getComplianceIntegration.remediationEnabled ?? false,
    }),
    [data]
  );

  // we optimistically assume that an error in "get" is a 404. We don't have any other info
  if (getError) {
    return <Page404 />;
  }

  return (
    <ComplianceSourceWizard
      initialValues={initialValues}
      onSubmit={values =>
        updateComplianceSource({
          variables: {
            input: {
              integrationId: match.params.id,
              integrationLabel: values.integrationLabel,
              cweEnabled: values.cweEnabled,
              remediationEnabled: values.remediationEnabled,
            },
          },
        })
      }
    />
  );
};

export default withSEO({ title: 'Edit Cloud Security Source' })(EditComplianceSource);
