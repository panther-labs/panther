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
import { Card, useSnackbar } from 'pouncejs';
import urls from 'Source/urls';
import Page404 from 'Pages/404';
import useRouter from 'Hooks/useRouter';
import withSEO from 'Hoc/withSEO';
import S3LogSourceWizard from 'Components/wizards/S3LogSourceWizard';
import { extractErrorMessage } from 'Helpers/utils';
import { useGetS3LogSource } from './graphql/getS3LogSource.generated';
import { useUpdateS3LogSource } from './graphql/updateS3LogSource.generated';

const EditS3LogSource: React.FC = () => {
  const { pushSnackbar } = useSnackbar();
  const { match, history } = useRouter<{ id: string }>();
  const { data, error: getError } = useGetS3LogSource({
    variables: { id: match.params.id },
    onError: error => {
      pushSnackbar({
        title: extractErrorMessage(error) || 'An unknown error occurred',
        variant: 'error',
      });
    },
  });

  const [updateLogSource, { error: updateError }] = useUpdateS3LogSource({
    onCompleted: () => history.push(urls.logAnalysis.sources.list()),
  });

  const initialValues = React.useMemo(
    () => ({
      integrationId: data?.getS3LogIntegration?.integrationId,
      initialStackName: data?.getS3LogIntegration?.stackName,
      awsAccountId: data?.getS3LogIntegration?.awsAccountId ?? 'Loading...',
      integrationLabel: data?.getS3LogIntegration?.integrationLabel ?? 'Loading...',
      s3Bucket: data?.getS3LogIntegration?.s3Bucket ?? 'Loading...',
      logTypes: data?.getS3LogIntegration?.logTypes ?? [],
      s3Prefix: data?.getS3LogIntegration?.s3Prefix ?? '',
      kmsKey: data?.getS3LogIntegration?.kmsKey ?? '',
    }),
    [data]
  );

  // we optimistically assume that an error in "get" is a 404. We don't have any other info
  if (getError) {
    return <Page404 />;
  }

  return (
    <Card p={9} mb={6}>
      <S3LogSourceWizard
        initialValues={initialValues}
        externalErrorMessage={updateError && extractErrorMessage(updateError)}
        onSubmit={values =>
          updateLogSource({
            variables: {
              input: {
                integrationId: values.integrationId,
                integrationLabel: values.integrationLabel,
                s3Bucket: values.s3Bucket,
                logTypes: values.logTypes,
                s3Prefix: values.s3Prefix || null,
                kmsKey: values.kmsKey || null,
              },
            },
          })
        }
      />
    </Card>
  );
};

export default withSEO({ title: 'Edit S3 Log Source' })(EditS3LogSource);
