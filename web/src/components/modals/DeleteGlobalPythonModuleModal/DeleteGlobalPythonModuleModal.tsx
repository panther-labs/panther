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
import { ModalProps, useSnackbar } from 'pouncejs';
import useRouter from 'Hooks/useRouter';
import urls from 'Source/urls';
import { GlobalPythonModuleTeaser } from 'Source/graphql/fragments/GlobalPythonModuleTeaser.generated';
import { GlobalPythonModuleFull } from 'Source/graphql/fragments/GlobalPythonModuleFull.generated';
import { useDeleteGlobalPythonModule } from './graphql/deleteGlobalPythonModule.generated';
import OptimisticConfirmModal from '../OptimisticConfirmModal';

export interface DeleteGlobalPythonModuleModalProps extends ModalProps {
  globalPythonModule: GlobalPythonModuleTeaser | GlobalPythonModuleFull;
}

const DeleteGlobalModal: React.FC<DeleteGlobalPythonModuleModalProps> = ({
  globalPythonModule,
  ...rest
}) => {
  const { location, history } = useRouter<{ id?: string }>();
  const { pushSnackbar } = useSnackbar();
  const globalName = globalPythonModule.id;
  const [confirm] = useDeleteGlobalPythonModule({
    variables: {
      input: {
        globals: [
          {
            id: globalPythonModule.id,
          },
        ],
      },
    },
    optimisticResponse: {
      deleteGlobalPythonModule: true,
    },
    update: async cache => {
      cache.modify('ROOT_QUERY', {
        listGlobalPythonModules: (data, helpers) => {
          const globalRef = helpers.toReference(globalPythonModule);
          return {
            ...data,
            globals: data.globals.filter(p => p.__ref !== globalRef.__ref),
          };
        },
      });

      cache.gc();
    },
    onCompleted: () => {
      pushSnackbar({
        variant: 'success',
        title: `Successfully deleted global module: ${globalName}`,
      });
    },
    onError: () => {
      pushSnackbar({
        variant: 'error',
        title: `Failed to delete global module: ${globalName}`,
      });
    },
  });

  function onConfirm() {
    if (location.pathname.includes(globalPythonModule.id)) {
      // if we were on the particular policy's details page or edit page --> redirect on delete
      history.push(urls.settings.globalPythonModules.list());
    }
    return confirm();
  }
  return (
    <OptimisticConfirmModal
      title={`Delete ${globalName}`}
      subtitle={`Are you sure you want to delete ${globalName}?`}
      onConfirm={onConfirm}
      {...rest}
    />
  );
};

export default DeleteGlobalModal;
