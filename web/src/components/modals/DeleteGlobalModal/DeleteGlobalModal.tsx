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
import useRouter from 'Hooks/useRouter';
import urls from 'Source/urls';
import { GlobalModuleTeaser } from 'Source/graphql/fragments/GlobalModuleTeaser.generated';
import { GlobalModuleFull } from 'Source/graphql/fragments/GlobalModuleFull.generated';
import { useDeleteGlobalModule } from './graphql/deleteGlobalModule.generated';
import OptimisticConfirmModal from '../OptimisticConfirmModal';

export interface DeleteGlobalModalProps {
  global: GlobalModuleTeaser | GlobalModuleFull;
}

const DeleteGlobalModal: React.FC<DeleteGlobalModalProps> = ({ global }) => {
  const { location, history } = useRouter<{ id?: string }>();
  const { pushSnackbar } = useSnackbar();
  const globalName = global.id;
  const [confirm] = useDeleteGlobalModule({
    variables: {
      input: {
        globals: [
          {
            id: global.id,
          },
        ],
      },
    },
    optimisticResponse: {
      deleteGlobalPythonModule: true,
    },
    update: async cache => {
      cache.modify('ROOT_QUERY', {
        listGlobalModules: (data, helpers) => {
          const globalRef = helpers.toReference({
            __typename: 'GlobalModule',
            id: global.id,
          });
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
    if (location.pathname.includes(global.id)) {
      // if we were on the particular policy's details page or edit page --> redirect on delete
      history.push(urls.compliance.policies.list());
    }
    return confirm();
  }
  return (
    <OptimisticConfirmModal
      title={`Delete ${globalName}`}
      subtitle={`Are you sure you want to delete ${globalName}?`}
      onConfirm={onConfirm}
    />
  );
};

export default DeleteGlobalModal;
