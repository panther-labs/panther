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

import isEmpty from 'lodash/isEmpty';
import pick from 'lodash/pick';
import pickBy from 'lodash/pickBy';

import { ALL_TYPES, sanitizeLogTypes } from 'Pages/ListAlerts/ListAlertBreadcrumbFilters';

import FormikCombobox from 'Components/fields/ComboBox';
import FormikMultiCombobox from 'Components/fields/MultiComboBox';
import FormikAutosave from 'Components/utils/Autosave';
import Breadcrumbs from 'Components/Breadcrumbs';

import useRequestParamsWithoutPagination from 'Hooks/useRequestParamsWithoutPagination';
import { useListAvailableLogTypes } from 'Source/graphql/queries/listAvailableLogTypes.generated';

const filterKeys = ['logTypes', 'tags'];

export type ListRulesBreadcrumbFiltersValues = Pick<ListRulesInput, 'tags' | 'logTypes'>;

const ListRulesBreadcrumbFilters: React.FC = () => {
  const { data, loading: logTypesLoading, error: logTypesError } = useListAvailableLogTypes();

  const { requestParams, setRequestParams } = useRequestParamsWithoutPagination<ListRulesInput>();

  const availableLogTypes = React.useMemo(
    () =>
      data?.listAvailableLogTypes.logTypes
        ? [ALL_TYPES, ...data.listAvailableLogTypes.logTypes]
        : [],
    [data]
  );

  const initialFilterValues = React.useMemo(() => {
    const { logTypes, ...params } = requestParams;
    return {
      ...pick(params, filterKeys),
      logTypes: logTypes && logTypes?.length > 0 ? logTypes : [ALL_TYPES],
      tags: [],
    } as ListRulesBreadcrumbFiltersValues;
  }, [requestParams]);

  const onFiltersChange = React.useCallback(
    values => {
      const { logTypes, ...rest } = values;
      const sanitizedLogTypes = sanitizeLogTypes(logTypes);
      const params = pickBy(
        { ...requestParams, ...rest, logTypes: sanitizedLogTypes },
        param => !isEmpty(param)
      );
      setRequestParams(params);
    },
    [requestParams, setRequestParams]
  );

  return (
    <Breadcrumbs.Actions>
      <Flex justify="flex-end">
        <Formik<ListRulesBreadcrumbFiltersValues>
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
                />
              </Box>
              {!logTypesLoading && !logTypesError && (
                <Field
                  as={FormikCombobox}
                  variant="solid"
                  label="Log Type"
                  name="logTypes"
                  items={availableLogTypes}
                />
              )}
            </Flex>
          </Form>
        </Formik>
      </Flex>
    </Breadcrumbs.Actions>
  );
};

export default React.memo(ListRulesBreadcrumbFilters);
