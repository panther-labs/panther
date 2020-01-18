/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
import { MutationTuple } from '@apollo/client';
import useRouter from 'Hooks/useRouter';

interface UseCreateRuleProps<T> {
  mutation: MutationTuple<T, { [key: string]: any }>;
  getRedirectUri: (data: T) => string;
}

function useCreateRule<T>({ mutation, getRedirectUri }: UseCreateRuleProps<T>) {
  const { history } = useRouter();
  const [createRule, { data, error }] = mutation;

  const handleSubmit = React.useCallback(async values => {
    await createRule({ variables: { input: values } });
  }, []);

  React.useEffect(() => {
    if (data) {
      // After all is ok, navigate to the newly created resource
      history.push(getRedirectUri(data));
    }
  }, [data]);

  return { handleSubmit, data, error };
}

export default useCreateRule;
