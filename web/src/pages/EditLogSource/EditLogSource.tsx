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

import React from 'react';
import { Card, useSnackbar } from 'pouncejs';
import urls from 'Source/urls';
import Page404 from 'Pages/404';
import useRouter from 'Hooks/useRouter';
import { extractErrorMessage } from 'Helpers/utils';
import LogSourceWizard from 'Components/wizards/LogSourceWizard';
import { useGetLogSource } from './graphql/getLogSource.generated';
import { useUpdateLogSource } from './graphql/updateLogSource.generated';

const EditLogSource: React.FC = () => {
  const { pushSnackbar } = useSnackbar();
  const { match, history } = useRouter<{ id: string }>();
  const { data, error: getError } = useGetLogSource({
    variables: { id: match.params.id },
    onError: error => {
      pushSnackbar({
        title: extractErrorMessage(error) || 'An unknown error occured',
        variant: 'error',
      });
    },
  });

  const [updateLogSource, { error: updateError }] = useUpdateLogSource({
    onCompleted: () => history.push(urls.logAnalysis.sources.list()),
  });

  const initialValues = React.useMemo(
    () => ({
      integrationId: data?.getLogIntegration.integrationId,
      awsAccountId: data?.getLogIntegration.awsAccountId ?? 'Loading...',
      integrationLabel: data?.getLogIntegration.integrationLabel ?? 'Loading...',
      s3Bucket: data?.getLogIntegration.s3Bucket ?? 'Loading...',
      s3Prefix: data?.getLogIntegration.s3Prefix ?? 'Loading...',
      kmsKey: data?.getLogIntegration.kmsKey ?? 'Loading...',
      logTypes: data?.getLogIntegration.logTypes ?? [],
    }),
    [data]
  );

  // we optimistically assume that an error in "get" is a 404. We don't have any other info
  if (getError) {
    return <Page404 />;
  }

  return (
    <Card p={9} mb={6}>
      <LogSourceWizard
        initialValues={initialValues}
        externalErrorMessage={updateError && extractErrorMessage(updateError)}
        onSubmit={values =>
          updateLogSource({
            variables: {
              input: {
                integrationId: values.integrationId,
                integrationLabel: values.integrationLabel,
                s3Bucket: values.s3Bucket,
                s3Prefix: values.s3Prefix,
                kmsKey: values.kmsKey,
                logTypes: values.logTypes,
              },
            },
          })
        }
      />
    </Card>
  );
};

export default EditLogSource;
