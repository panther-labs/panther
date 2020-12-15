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
import { EventEnum, SrcEnum, trackError, TrackErrorEnum, trackEvent } from 'Helpers/analytics';
import { extractErrorMessage } from 'Helpers/utils';
import SqsSourceWizard from 'Components/wizards/SqsSourceWizard';
import { useGetSqsLogSource } from './graphql/getSqsLogSource.generated';
import { useUpdateSqsLogSource } from './graphql/updateSqsLogSource.generated';

const EditSqsLogSource: React.FC = () => {
  const { pushSnackbar } = useSnackbar();
  const { match } = useRouter<{ id: string }>();
  const { data, error: getError } = useGetSqsLogSource({
    variables: { id: match.params.id },
    onError: error => {
      pushSnackbar({
        title: extractErrorMessage(error) || 'An unknown error occurred',
        variant: 'error',
      });
    },
  });

  const [updateSqsLogSource] = useUpdateSqsLogSource({
    onCompleted: () =>
      trackEvent({ event: EventEnum.UpdatedLogSource, src: SrcEnum.LogSources, ctx: 'SQS' }),
    onError: err => {
      trackError({
        event: TrackErrorEnum.FailedToUpdateLogSource,
        src: SrcEnum.LogSources,
        ctx: 'SQS',
      });

      // Defining an `onError` catches the API exception. We need to re-throw it so that it
      // can be caught by `ValidationPanel` which checks for API errors
      throw err;
    },
  });

  const initialValues = React.useMemo(
    () => ({
      integrationId: match.params.id,
      integrationLabel: data?.getSqsLogIntegration?.integrationLabel ?? 'Loading...',
      logTypes: data?.getSqsLogIntegration.sqsConfig.logTypes ?? [],
      allowedPrincipalArns: data?.getSqsLogIntegration.sqsConfig.allowedPrincipalArns ?? [],
      allowedSourceArns: data?.getSqsLogIntegration.sqsConfig.allowedSourceArns ?? [],
      queueUrl: data?.getSqsLogIntegration.sqsConfig.queueUrl,
    }),
    [data]
  );

  // we optimistically assume that an error in "get" is a 404. We don't have any other info
  if (getError) {
    return <Page404 />;
  }

  return (
    <SqsSourceWizard
      initialValues={initialValues}
      onSubmit={values =>
        updateSqsLogSource({
          variables: {
            input: {
              integrationId: values.integrationId,
              integrationLabel: values.integrationLabel,
              sqsConfig: {
                logTypes: values.logTypes,
                allowedPrincipalArns: values.allowedPrincipalArns,
                allowedSourceArns: values.allowedSourceArns,
              },
            },
          },
        })
      }
    />
  );
};

export default withSEO({ title: 'Edit SQS Log Source' })(EditSqsLogSource);
