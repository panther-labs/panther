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
import DataModelForm from 'Components/forms/DataModelForm';
import { extractErrorMessage } from 'Helpers/utils';
import { EventEnum, SrcEnum, trackError, TrackErrorEnum, trackEvent } from 'Helpers/analytics';
import withSEO from 'Hoc/withSEO';
import useRouter from 'Hooks/useRouter';
import Page404 from 'Pages/404/404';
import { useGetDataModel } from './graphql/getDataModel.generated';
import { useUpdateDataModel } from './graphql/updateDataModel.generated';

const EditDataModel: React.FC = () => {
  const { match } = useRouter<{ id: string }>(); // prettier-ignore
  const { pushSnackbar } = useSnackbar();

  const { data, error: getError } = useGetDataModel({ variables: { id: match.params.id } });

  const [updateDataModel] = useUpdateDataModel({
    onCompleted: () => {
      trackEvent({ event: EventEnum.UpdatedDataModel, src: SrcEnum.DataModels });
      pushSnackbar({
        variant: 'success',
        title: 'Successfully updated your Data Model',
      });
    },
    onError: error => {
      trackError({ event: TrackErrorEnum.FailedToUpdateDataModel, src: SrcEnum.DataModels });
      pushSnackbar({
        variant: 'error',
        title: extractErrorMessage(error),
      });
    },
  });

  const initialValues = React.useMemo(
    () => ({
      id: match.params.id,
      displayName: data?.getDataModel.displayName ?? '',
      logType: data?.getDataModel.logTypes?.[0] ?? null,
      enabled: data?.getDataModel.enabled ?? true,
      mappings: data?.getDataModel.mappings ?? [{ name: '', method: '', path: '' }],
      body: data?.getDataModel.body ?? '',
    }),
    [data]
  );

  // we optimistically assume that an error in "get" is a 404. We don't have any other info
  if (getError) {
    return <Page404 />;
  }
  return (
    <DataModelForm
      initialValues={initialValues}
      onSubmit={values =>
        updateDataModel({
          variables: {
            input: {
              id: values.id,
              displayName: values.displayName,
              logTypes: [values.logType],
              enabled: values.enabled,
              mappings: values.mappings,
              body: values.body,
            },
          },
        })
      }
    />
  );
};

export default withSEO({ title: ({ match }) => `Update ${match.params.id}` })(EditDataModel);
