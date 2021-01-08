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
import { useUpdateCustomLog } from './graphql/updateCustomLog.generated';
import { useGetCustomLogDetails } from '../CustomLogDetails/graphql/getCustomLogDetails.generated';
import Skeleton from './Skeleton';

const EditCustomLog: React.FC = () => {
  const { match: { params: { logType } } } = useRouter<{ logType: string }>(); // prettier-ignore
  const { pushSnackbar } = useSnackbar();
  const { data, loading } = useGetCustomLogDetails({
    variables: { input: { logType } },
  });

  const [updateCustomLog] = useUpdateCustomLog({
    onCompleted: ({ updateCustomLog: { error } }) => {
      if (!error) {
        trackEvent({ event: EventEnum.UpdatedCustomLog, src: SrcEnum.CustomLogs });
        pushSnackbar({
          variant: 'success',
          title: 'Successfully updated custom log schema!',
        });
      } else {
        trackError({ event: TrackErrorEnum.FailedToUpdateLogSource, src: SrcEnum.CustomLogs });
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

  if (loading) {
    return <Skeleton />;
  }
  const { record: customLog } = data.getCustomLog;

  const initialValues = {
    revision: customLog.revision,
    name: customLog.logType,
    referenceUrl: customLog.referenceURL,
    schema: customLog.logSpec,
    description: customLog.description,
  };
  return (
    <React.Fragment>
      <Panel title="Edit Custom Schema">
        <CustomLogForm
          initialValues={initialValues}
          onSubmit={values =>
            updateCustomLog({
              variables: {
                input: {
                  revision: customLog.revision,
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

export default compose(withSEO({ title: 'Edit Custom Schema' }))(EditCustomLog);
