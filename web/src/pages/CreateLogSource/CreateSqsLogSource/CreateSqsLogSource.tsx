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
import { extractErrorMessage } from 'Helpers/utils';
import urls from 'Source/urls';
import useRouter from 'Hooks/useRouter';
import SqsSourceWizard from 'Components/wizards/SqsSourceWizard';
import { useAddSqsLogSource } from './graphql/addSqsLogSource.generated';

const initialValues = {
  integrationLabel: '',
  logTypes: [],
  allowedPrincipals: [],
  allowedSourceArns: [],
};

const CreateSqsLogSource: React.FC = () => {
  const { history } = useRouter();
  const [addSqsLogSource, { error: sqsError }] = useAddSqsLogSource({
    update: (cache, { data }) => {
      cache.modify('ROOT_QUERY', {
        listLogIntegrations: (queryData, { toReference }) => {
          const addedIntegrationCacheRef = toReference(data.addSqsLogIntegration);
          return queryData ? [addedIntegrationCacheRef, ...queryData] : [addedIntegrationCacheRef];
        },
      });
    },
    onCompleted: data =>
      history.push(urls.logAnalysis.sources.edit(data.addSqsLogIntegration.integrationId, 'sqs')),
  });

  return (
    <SqsSourceWizard
      initialValues={initialValues}
      externalErrorMessage={sqsError && extractErrorMessage(sqsError)}
      onSubmit={values =>
        addSqsLogSource({
          variables: {
            input: {
              integrationLabel: values.integrationLabel,
              sqsConfig: {
                logTypes: values.logTypes,
                allowedPrincipals: values.allowedPrincipals,
                allowedSourceArns: values.allowedSourceArns,
              },
            },
          },
        })
      }
    />
  );
};

export default withSEO({ title: 'New SQS Source' })(CreateSqsLogSource);
