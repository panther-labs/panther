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
import urls from 'Source/urls';
import { ListDataModelsDocument } from 'Pages/ListDataModels';
import { useCreateDataModel } from './graphql/createDataModel.generated';

const initialValues = {
  id: '',
  displayName: '',
  logType: null,
  enabled: true,
  mappings: [{ name: '', method: '', path: '' }],
  body: '',
};

const CreateDataModel: React.FC = () => {
  const { history } = useRouter();
  const { pushSnackbar } = useSnackbar();

  const [createDataModel] = useCreateDataModel({
    update: (cache, { data: { addDataModel: dataModel } }) => {
      cache.modify('ROOT_QUERY', {
        listDataModels: (dataModels, { toReference }) => {
          const dataModelRef = toReference(dataModel);

          return {
            ...dataModels,
            models: dataModels.models ? [dataModelRef, ...dataModels.models] : [dataModelRef],
          };
        },
      });
    },
    onCompleted: () => {
      trackEvent({ event: EventEnum.AddedDataModel, src: SrcEnum.DataModels });
      history.push(urls.logAnalysis.dataModels.list());
    },
    onError: error => {
      trackError({ event: TrackErrorEnum.FailedToAddDataModel, src: SrcEnum.DataModels });
      pushSnackbar({
        variant: 'error',
        title: extractErrorMessage(error),
      });
    },
    refetchQueries: [{ query: ListDataModelsDocument, variables: { input: {} } }],
    awaitRefetchQueries: true,
  });

  return (
    <DataModelForm
      initialValues={initialValues}
      onSubmit={values =>
        createDataModel({
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

export default withSEO({ title: 'New Data Model' })(CreateDataModel);
