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
import S3LogSourceWizard from 'Components/wizards/S3LogSourceWizard';
import { EventEnum, SrcEnum, trackError, trackEvent, TrackErrorEnum } from 'Helpers/analytics';
import { extractErrorMessage } from 'Helpers/utils';
import { useGetS3LogSource } from './graphql/getS3LogSource.generated';
import { useUpdateS3LogSource } from './graphql/updateS3LogSource.generated';

const EditS3LogSource: React.FC = () => {
  const { pushSnackbar } = useSnackbar();
  const { match } = useRouter<{ id: string }>();
  const { data, error: getError } = useGetS3LogSource({
    variables: { id: match.params.id },
    onError: error => {
      pushSnackbar({
        title: extractErrorMessage(error) || 'An unknown error occurred',
        variant: 'error',
      });
    },
  });

  const [updateLogSource] = useUpdateS3LogSource({
    onCompleted: () =>
      trackEvent({ event: EventEnum.UpdatedLogSource, src: SrcEnum.LogSources, ctx: 'S3' }),
    onError: err => {
      trackError({
        event: TrackErrorEnum.FailedToUpdateLogSource,
        src: SrcEnum.LogSources,
        ctx: 'S3',
      });

      // Defining an `onError` catches the API exception. We need to re-throw it so that it
      // can be caught by `ValidationPanel` which checks for API errors
      throw err;
    },
  });

  const initialValues = React.useMemo(
    () => ({
      integrationId: match.params.id,
      initialStackName: data?.getS3LogIntegration?.stackName,
      awsAccountId: data?.getS3LogIntegration?.awsAccountId ?? 'Loading...',
      integrationLabel: data?.getS3LogIntegration?.integrationLabel ?? 'Loading...',
      s3Bucket: data?.getS3LogIntegration?.s3Bucket ?? 'Loading...',
      s3PrefixLogTypes: data?.getS3LogIntegration.s3PrefixLogTypes ?? [
        { prefix: '', logTypes: [] },
      ],
      kmsKey: data?.getS3LogIntegration?.kmsKey ?? '',
    }),
    [data]
  );

  // we optimistically assume that an error in "get" is a 404. We don't have any other info
  if (getError) {
    return <Page404 />;
  }

  return (
    <S3LogSourceWizard
      initialValues={initialValues}
      onSubmit={values =>
        updateLogSource({
          variables: {
            input: {
              integrationId: values.integrationId,
              integrationLabel: values.integrationLabel,
              s3Bucket: values.s3Bucket,
              s3PrefixLogTypes: values.s3PrefixLogTypes,
              kmsKey: values.kmsKey || null,
            },
          },
        })
      }
    />
  );
};

export default withSEO({ title: 'Edit S3 Log Source' })(EditS3LogSource);
