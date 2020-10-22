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
import { Form, Formik, Field } from 'formik';
import { ListAlertsInput } from 'Generated/schema';
import { Flex } from 'pouncejs';
import useRequestParamsWithoutPagination from 'Hooks/useRequestParamsWithoutPagination';

import pickBy from 'lodash/pickBy';
import isEmpty from 'lodash/isEmpty';
import pick from 'lodash/pick';

import FormikDateRangeInput from 'Components/fields/DateRangeInput';
import FormikCombobox from 'Components/fields/ComboBox';
import FormikAutosave from 'Components/utils/Autosave';
import Breadcrumbs from 'Components/Breadcrumbs';
import { useListAvailableLogTypes } from 'Source/graphql/queries';

export type ListAlertsFiltersValues = Pick<
  ListAlertsInput,
  'logTypes' | 'createdAtAfter' | 'createdAtBefore'
>;

export const ALL_TYPES = 'All types';

export const sanitizeLogTypes = logTypes => {
  // Sanitize values coming from the URL as array and from the component as string.
  if (Array.isArray(logTypes)) {
    return logTypes.filter(type => type === 'ALL_TYPES');
  }
  return logTypes !== ALL_TYPES ? [logTypes] : [];
};

const filterKeys = ['logTypes', 'createdAtAfter', 'createdAtBefore'];
const ListAlertBreadcrumbFilters: React.FC = () => {
  const { data, loading: logTypesLoading, error: logTypesError } = useListAvailableLogTypes();

  const { requestParams, setRequestParams } = useRequestParamsWithoutPagination<ListAlertsInput>();

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
    } as ListAlertsFiltersValues;
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
        <Formik<ListAlertsFiltersValues>
          initialValues={initialFilterValues}
          onSubmit={onFiltersChange}
        >
          <Form>
            <FormikAutosave threshold={50} />
            <Flex spacing={4}>
              {!logTypesLoading && !logTypesError && (
                <Field
                  as={FormikCombobox}
                  variant="solid"
                  label="Log Type"
                  name="logTypes"
                  items={availableLogTypes}
                />
              )}
              <FormikDateRangeInput
                alignment="right"
                withPresets
                withTime
                variant="solid"
                format="MM/DD/YY HH:mm"
                labelStart="Date Start"
                labelEnd="Date End"
                placeholderStart="MM/DD/YY HH:mm"
                placeholderEnd="MM/DD/YY HH:mm"
                nameStart="createdAtAfter"
                nameEnd="createdAtBefore"
              />
            </Flex>
          </Form>
        </Formik>
      </Flex>
    </Breadcrumbs.Actions>
  );
};

export default React.memo(ListAlertBreadcrumbFilters);
