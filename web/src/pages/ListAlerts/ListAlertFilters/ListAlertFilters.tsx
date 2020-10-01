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
import { Box, Flex } from 'pouncejs';
import { ListAlertsInput, SeverityEnum, AlertStatusesEnum } from 'Generated/schema';
import useRequestParamsWithoutPagination from 'Hooks/useRequestParamsWithoutPagination';
import { capitalize } from 'Helpers/utils';

import pick from 'lodash/pick';

import FormikAutosave from 'Components/utils/Autosave';
import FormikMultiCombobox from 'Components/fields/MultiComboBox';
import FormikTextInput from 'Components/fields/TextInput';

export type ListAlertsInlineFiltersValues = Pick<
  ListAlertsInput,
  'severity' | 'status' | 'nameContains' | 'sortBy' | 'sortDir'
>;

const severityOptions = Object.values(SeverityEnum);
const statusOptions = Object.values(AlertStatusesEnum);

const filters = [
  'severity',
  'status',
  'nameContains',
  'sortBy',
  'sortDir',
] as (keyof ListAlertsInput)[];

const defaultValues = {
  nameContains: '',
  severity: [],
  status: [],
};
const ListAlertFilters: React.FC = () => {
  const { requestParams, updateRequestParams } = useRequestParamsWithoutPagination<
    ListAlertsInput
  >();

  const initialFilterValues = React.useMemo(
    () =>
      ({
        ...defaultValues,
        ...pick(requestParams, filters),
      } as ListAlertsInlineFiltersValues),
    [requestParams]
  );

  const onInlineFiltersChange = React.useCallback(
    (values: ListAlertsInlineFiltersValues) => {
      updateRequestParams(values);
    },
    [requestParams, updateRequestParams]
  );

  return (
    <Flex justify="flex-end">
      <Formik<ListAlertsInlineFiltersValues>
        initialValues={initialFilterValues}
        onSubmit={onInlineFiltersChange}
      >
        <Form>
          <FormikAutosave threshold={200} />
          <Flex spacing={4}>
            <Box width={300}>
              <Field
                name="nameContains"
                icon="search"
                iconAlignment="left"
                as={FormikTextInput}
                label="Filter Alerts by text"
              />
            </Box>
            <Box>
              <Field
                name="severity"
                as={FormikMultiCombobox}
                items={severityOptions}
                itemToString={(severity: SeverityEnum) => capitalize(severity.toLowerCase())}
                label="Severity"
              />
            </Box>
            <Box>
              <Field
                name="status"
                as={FormikMultiCombobox}
                items={statusOptions}
                itemToString={(status: AlertStatusesEnum) => capitalize(status.toLowerCase())}
                label="Status"
              />
            </Box>
          </Flex>
        </Form>
      </Formik>
    </Flex>
  );
};

export default React.memo(ListAlertFilters);
