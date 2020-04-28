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
import { Card } from 'pouncejs';
import urls from 'Source/urls';
import { extractErrorMessage } from 'Helpers/utils';
import useRouter from 'Hooks/useRouter';
import LogSourceWizard from 'Components/wizards/LogSourceWizard';
import { useAddLogSource } from './graphql/addLogSource.generated';

const initialValues = {
  integrationLabel: '',
  awsAccountId: '',
  s3Bucket: '',
  s3Prefix: '',
  kmsKey: '',
  logTypes: [],
};

const CreateLogSource: React.FC = () => {
  const { history } = useRouter();
  const [addLogSource, { error }] = useAddLogSource({
    update: (cache, { data: { addLogIntegration } }) => {
      cache.modify('ROOT_QUERY', {
        listLogIntegrations: (queryData, { toReference }) => {
          const addedIntegrationCacheRef = toReference(addLogIntegration);
          return queryData ? [addedIntegrationCacheRef, ...queryData] : [addedIntegrationCacheRef];
        },
      });
    },
    onCompleted: () => history.push(urls.logAnalysis.sources.list()),
  });

  return (
    <Card p={9} mb={6}>
      <LogSourceWizard
        initialValues={initialValues}
        externalErrorMessage={error && extractErrorMessage(error)}
        onSubmit={values =>
          addLogSource({
            variables: {
              input: {
                integrationLabel: values.integrationLabel,
                awsAccountId: values.awsAccountId,
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

export default CreateLogSource;
