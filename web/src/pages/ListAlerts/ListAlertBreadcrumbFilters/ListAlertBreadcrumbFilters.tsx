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
import { Form, Formik } from 'formik';
import { ListAlertsInput } from 'Generated/schema';
import { Flex } from 'pouncejs';
import useRequestParamsWithoutPagination from 'Hooks/useRequestParamsWithoutPagination';

import pick from 'lodash/pick';

import FormikDateRangeInput from 'Components/fields/DateRangeInput';
import FormikAutosave from 'Components/utils/Autosave';
import Breadcrumbs from 'Components/Breadcrumbs';

export type ListAlertsFiltersValues = {
  createdAtBefore: string;
  createdAtAfter: string;
};

const filterKeys: (keyof Partial<ListAlertsInput>)[] = ['createdAtAfter', 'createdAtBefore'];

const ListAlertBreadcrumbFilters: React.FC = () => {
  const { requestParams, updateRequestParams } = useRequestParamsWithoutPagination<
    ListAlertsInput
  >();

  const initialFilterValues = React.useMemo(() => {
    return pick(requestParams, filterKeys) as ListAlertsFiltersValues;
  }, [requestParams]);

  return (
    <Breadcrumbs.Actions>
      <Flex justify="flex-end">
        <Formik<ListAlertsFiltersValues>
          enableReinitialize
          initialValues={initialFilterValues}
          onSubmit={updateRequestParams}
        >
          <Form>
            <FormikAutosave threshold={50} />
            <FormikDateRangeInput
              alignment="right"
              withPresets
              withTime
              variant="solid"
              format="MM/DD/YYYY HH:mm"
              labelStart="Date Start"
              labelEnd="Date End"
              placeholderStart="MM/DD/YY HH:mm"
              placeholderEnd="MM/DD/YY HH:mm"
              nameStart="createdAtAfter"
              nameEnd="createdAtBefore"
            />
          </Form>
        </Formik>
      </Flex>
    </Breadcrumbs.Actions>
  );
};

export default React.memo(ListAlertBreadcrumbFilters);
