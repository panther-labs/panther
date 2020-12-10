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
import { Link, Text, useSnackbar } from 'pouncejs';
import Panel from 'Components/Panel';
import CustomLogForm from 'Components/forms/CustomLogForm';
import { CUSTOM_LOG_TYPES_DOC_URL } from 'Source/constants';
import { extractErrorMessage } from 'Helpers/utils';
import { EventEnum, SrcEnum, trackError, TrackErrorEnum, trackEvent } from 'Helpers/analytics';
import { compose } from 'Helpers/compose';
import withSEO from 'Hoc/withSEO';
import useRouter from 'Hooks/useRouter';
import urls from 'Source/urls';
import { useCreateCustomLog } from './graphql/createCustomLog.generated';

const initialValues = {
  name: '',
  description: '',
  referenceUrl: '',
  schema: '',
};

const CreateCustomLog: React.FC = () => {
  const { history } = useRouter();
  const { pushSnackbar } = useSnackbar();
  const [createCustomLog] = useCreateCustomLog({
    update: (cache, { data: { addCustomLog } }) => {
      const { record } = addCustomLog;
      if (record) {
        cache.modify('ROOT_QUERY', {
          listCustomLogs: (queryData, { toReference }) => {
            const customLogRef = toReference(record);
            return queryData ? [customLogRef, ...queryData] : [customLogRef];
          },
          listAvailableLogTypes: queryData => {
            return {
              ...queryData,
              logTypes: [...queryData.logTypes, record.logType],
            };
          },
        });
      }
    },
    onCompleted: ({ addCustomLog: { error, record } }) => {
      if (!error) {
        trackEvent({ event: EventEnum.AddedCustomLog, src: SrcEnum.CustomLogs });
        history.push(urls.logAnalysis.customLogs.details(record.logType));
      } else {
        trackError({ event: TrackErrorEnum.FailedToAddCustomLog, src: SrcEnum.CustomLogs });
        pushSnackbar({ variant: 'error', title: error.message });
      }
    },
    onError: error => {
      trackError({ event: TrackErrorEnum.FailedToAddCustomLog, src: SrcEnum.CustomLogs });
      pushSnackbar({
        variant: 'error',
        title: extractErrorMessage(error),
      });
    },
  });

  return (
    <React.Fragment>
      <Panel title="New Custom Schema">
        <CustomLogForm
          initialValues={initialValues}
          onSubmit={values =>
            createCustomLog({
              variables: {
                input: {
                  logType: values.name,
                  description: values.description,
                  referenceURL: values.referenceUrl,
                  logSpec: values.schema,
                },
              },
            })
          }
        />
      </Panel>
      <Text my={5} fontSize="medium">
        Need to know more about how to write custom schemas?{' '}
        <Link external href={CUSTOM_LOG_TYPES_DOC_URL}>
          Read our documentation
        </Link>
      </Text>
    </React.Fragment>
  );
};

export default compose(withSEO({ title: 'New Custom Schema' }))(CreateCustomLog);
