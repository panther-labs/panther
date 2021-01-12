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
import { Alert, Link, Text, useSnackbar } from 'pouncejs';
import Panel from 'Components/Panel';
import CustomLogForm from 'Components/forms/CustomLogForm';
import { CUSTOM_LOG_TYPES_DOC_URL } from 'Source/constants';
import { ErrorCodeEnum } from 'Generated/schema';
import { extractErrorMessage } from 'Helpers/utils';
import {
  EventEnum,
  SrcEnum,
  trackError,
  TrackErrorEnum,
  trackEvent,
  PageViewEnum,
} from 'Helpers/analytics';
import { compose } from 'Helpers/compose';
import Page404 from 'Pages/404';
import withSEO from 'Hoc/withSEO';
import useRouter from 'Hooks/useRouter';

import useTrackPageView from 'Hooks/useTrackPageView';
import { useUpdateCustomLog } from './graphql/updateCustomLog.generated';
import { useGetCustomLogDetails } from '../CustomLogDetails/graphql/getCustomLogDetails.generated';

const EditCustomLog: React.FC = () => {
  useTrackPageView(PageViewEnum.CustomLogEditing);

  const { match: { params: { logType } } } = useRouter<{ logType: string }>(); // prettier-ignore
  const { pushSnackbar } = useSnackbar();
  const { data, error: uncontrolledError } = useGetCustomLogDetails({
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

  const { record: customLog, error: controlledError } = data?.getCustomLog || {};

  const initialValues = React.useMemo(
    () => ({
      revision: data?.getCustomLog?.record?.revision,
      name: data?.getCustomLog?.record?.logType ?? 'Loading...',
      referenceUrl: data?.getCustomLog?.record?.referenceURL ?? 'Loading...',
      schema: data?.getCustomLog?.record?.logSpec ?? 'Loading...',
      description: data?.getCustomLog?.record?.description ?? 'Loading...',
    }),
    [data]
  );

  if (controlledError) {
    return (
      <Alert
        variant="error"
        title="Couldn't load your custom schema"
        description={extractErrorMessage(uncontrolledError)}
      />
    );
  }

  if (controlledError) {
    if (controlledError.code === ErrorCodeEnum.NotFound) {
      return <Page404 />;
    }

    return (
      <Alert
        variant="error"
        title="Couldn't load your custom schema"
        description={controlledError.message}
      />
    );
  }

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
