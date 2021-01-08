import React from 'react';
import { ModalProps, useSnackbar } from 'pouncejs';
import { DataModel } from 'Generated/schema';
import { EventEnum, SrcEnum, trackError, TrackErrorEnum, trackEvent } from 'Helpers/analytics';
import OptimisticConfirmModal from 'Components/modals/OptimisticConfirmModal';
import { useDeleteDataModel } from './graphql/deleteDataModel.generated';

export interface DeleteDataModelModalProps extends ModalProps {
  dataModel: DataModel;
}

const DeleteDataModelModal: React.FC<DeleteDataModelModalProps> = ({ dataModel, ...rest }) => {
  const { pushSnackbar } = useSnackbar();
  const [deleteDataModel] = useDeleteDataModel({
    variables: { input: { dataModels: [{ id: dataModel.id }] } },

    // issue: https://github.com/apollographql/apollo-client/issues/5790
    update: cache => {
      cache.modify('ROOT_QUERY', {
        listDataModels(dataModels, { toReference }) {
          const deletedDataModel = toReference({ __typename: 'DataModel', id: dataModel.id });
          return {
            ...dataModels,
            models: dataModels.models.filter(d => d.__ref !== deletedDataModel.__ref),
          };
        },
      });
      cache.gc();
    },
    onCompleted: () => {
      trackEvent({ event: EventEnum.DeletedDataModel, src: SrcEnum.DataModels });
    },
    onError: () => {
      pushSnackbar({
        variant: 'error',
        title: 'Failed to delete your Data Model',
      });
      trackError({ event: TrackErrorEnum.FailedToDeleteDataModel, src: SrcEnum.DataModels });
    },
  });

  return (
    <OptimisticConfirmModal
      onConfirm={deleteDataModel}
      title="Delete Data Model"
      subtitle={[`Are you sure you want to delete `, <b key={0}>{dataModel.displayName}?</b>]}
      {...rest}
    />
  );
};

export default DeleteDataModelModal;
