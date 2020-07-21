/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
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
