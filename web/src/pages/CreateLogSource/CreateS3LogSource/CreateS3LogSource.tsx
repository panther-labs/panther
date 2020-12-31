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
import withSEO from 'Hoc/withSEO';
import S3LogSourceWizard from 'Components/wizards/S3LogSourceWizard';
import { EventEnum, SrcEnum, trackError, TrackErrorEnum, trackEvent } from 'Helpers/analytics';
import { useAddS3LogSource } from './graphql/addS3LogSource.generated';

const initialValues = {
  integrationLabel: '',
  awsAccountId: '',
  s3Bucket: '',
  kmsKey: '',
  s3PrefixLogTypes: [{ prefix: '', logTypes: [] }],
};

const CreateS3LogSource: React.FC = () => {
  const [addLogSource] = useAddS3LogSource({
    update: (cache, { data }) => {
      cache.modify('ROOT_QUERY', {
        listLogIntegrations: (queryData, { toReference }) => {
          const addedIntegrationCacheRef = toReference(data.addS3LogIntegration);
          return queryData ? [addedIntegrationCacheRef, ...queryData] : [addedIntegrationCacheRef];
        },
      });
    },
    onCompleted: () =>
      trackEvent({ event: EventEnum.AddedLogSource, src: SrcEnum.LogSources, ctx: 'S3' }),
    onError: err => {
      trackError({
        event: TrackErrorEnum.FailedToAddLogSource,
        src: SrcEnum.LogSources,
        ctx: 'S3',
      });

      // Defining an `onError` catches the API exception. We need to re-throw it so that it
      // can be caught by `ValidationPanel` which checks for API errors
      throw err;
    },
  });

  return (
    <S3LogSourceWizard
      initialValues={initialValues}
      onSubmit={values =>
        addLogSource({
          variables: {
            input: {
              integrationLabel: values.integrationLabel,
              awsAccountId: values.awsAccountId,
              s3Bucket: values.s3Bucket,
              s3PrefixLogTypes: values.s3PrefixLogTypes,
              kmsKey: values.kmsKey,
            },
          },
        })
      }
    />
  );
};

export default withSEO({ title: 'New S3 Source' })(CreateS3LogSource);
