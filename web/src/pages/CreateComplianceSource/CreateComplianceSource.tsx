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
import ComplianceSourceWizard from 'Components/wizards/ComplianceSourceWizard';
import { EventEnum, SrcEnum, trackError, TrackErrorEnum, trackEvent } from 'Helpers/analytics';
import { useAddComplianceSource } from './graphql/addComplianceSource.generated';

const initialValues = {
  awsAccountId: '',
  integrationLabel: '',
  cweEnabled: true,
  remediationEnabled: true,
  regionIgnoreList: [],
  resourceTypeIgnoreList: [],
};

const CreateComplianceSource: React.FC = () => {
  const [addComplianceSource] = useAddComplianceSource({
    update: (cache, { data: { addComplianceIntegration } }) => {
      cache.modify('ROOT_QUERY', {
        listComplianceIntegrations: (queryData, { toReference }) => {
          const addedIntegrationCacheRef = toReference(addComplianceIntegration);
          return queryData ? [addedIntegrationCacheRef, ...queryData] : [addedIntegrationCacheRef];
        },
      });
    },
    onCompleted: () =>
      trackEvent({ event: EventEnum.AddedComplianceSource, src: SrcEnum.ComplianceSources }),
    onError: err => {
      trackError({
        event: TrackErrorEnum.FailedToAddComplianceSource,
        src: SrcEnum.ComplianceSources,
      });

      // Defining an `onError` catches the API exception. We need to re-throw it so that it
      // can be caught by `ValidationPanel` which checks for API errors
      throw err;
    },
  });

  return (
    <ComplianceSourceWizard
      initialValues={initialValues}
      onSubmit={values =>
        addComplianceSource({
          variables: {
            input: {
              integrationLabel: values.integrationLabel,
              awsAccountId: values.awsAccountId,
              cweEnabled: values.cweEnabled,
              remediationEnabled: values.remediationEnabled,
              regionIgnoreList: values.regionIgnoreList,
              resourceTypeIgnoreList: values.resourceTypeIgnoreList,
            },
          },
        })
      }
    />
  );
};

export default withSEO({ title: 'New Cloud Security Source' })(CreateComplianceSource);
