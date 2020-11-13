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
import { ListRulesInput } from 'Generated/schema';
import { Box, Flex } from 'pouncejs';
import { Form, Formik, Field } from 'formik';

import pick from 'lodash/pick';

import { ALL_TYPES } from 'Pages/ListAlerts/ListAlertBreadcrumbFilters';

import FormikCombobox from 'Components/fields/ComboBox';
import FormikMultiCombobox from 'Components/fields/MultiComboBox';
import FormikAutosave from 'Components/utils/Autosave';
import Breadcrumbs from 'Components/Breadcrumbs';

import useRequestParamsWithPagination from 'Hooks/useRequestParamsWithPagination';
import { useListAvailableLogTypes } from 'Source/graphql/queries';

export type ListRulesBreadcrumbFiltersValues = {
  logType: string;
  tags: string[];
};

const filterKeys: (keyof Partial<ListRulesInput>)[] = ['logTypes', 'tags'];

const ListRulesBreadcrumbFilters: React.FC = () => {
  const { data, loading: logTypesLoading, error: logTypesError } = useListAvailableLogTypes();

  const { requestParams, updateRequestParamsAndResetPaging } = useRequestParamsWithPagination<
    ListRulesInput
  >();

  const availableLogTypes = React.useMemo(
    () =>
      data?.listAvailableLogTypes.logTypes
        ? [ALL_TYPES, ...data.listAvailableLogTypes.logTypes]
        : [],
    [data]
  );

  const initialFilterValues = React.useMemo(() => {
    const { logTypes, tags, ...params } = requestParams;
    return {
      ...pick(params, filterKeys),
      logType: logTypes?.length > 0 ? logTypes[0] : ALL_TYPES,
      tags: tags || [],
    } as ListRulesBreadcrumbFiltersValues;
  }, [requestParams]);

  const onFiltersChange = React.useCallback(
    ({ logType, ...rest }: ListRulesBreadcrumbFiltersValues) => {
      updateRequestParamsAndResetPaging({
        ...rest,
        logTypes: logType !== ALL_TYPES ? [logType] : undefined,
      });
    },
    [updateRequestParamsAndResetPaging]
  );

  return (
    <Breadcrumbs.Actions>
      <Flex justify="flex-end">
        <Formik<ListRulesBreadcrumbFiltersValues>
          enableReinitialize
          initialValues={initialFilterValues}
          onSubmit={onFiltersChange}
        >
          <Form>
            <FormikAutosave threshold={50} />
            <Flex spacing={4}>
              <Box width={250}>
                <Field
                  as={FormikMultiCombobox}
                  variant="solid"
                  label="Tags"
                  searchable
                  allowAdditions
                  name="tags"
                  items={[] as string[]}
                  placeholder="Type in tags to filter by..."
                />
              </Box>
              {!logTypesLoading && !logTypesError && (
                <Box width={250}>
                  <Field
                    as={FormikCombobox}
                    variant="solid"
                    label="Log Type"
                    name="logType"
                    items={availableLogTypes}
                    placeholder="Filter by log type"
                    searchable
                  />
                </Box>
              )}
            </Flex>
          </Form>
        </Formik>
      </Flex>
    </Breadcrumbs.Actions>
  );
};

export default React.memo(ListRulesBreadcrumbFilters);
