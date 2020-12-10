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
import { Alert, Box, Button, Card, Collapse, Flex } from 'pouncejs';
import { RESOURCE_TYPES } from 'Source/constants';
import GenerateFiltersGroup from 'Components/utils/GenerateFiltersGroup';
import { ComplianceStatusEnum, ListResourcesInput, ComplianceIntegration } from 'Generated/schema';
import { capitalize } from 'Helpers/utils';
import { useListComplianceSourceNames } from 'Source/graphql/queries';
import FormikTextInput from 'Components/fields/TextInput';
import FormikCombobox from 'Components/fields/ComboBox';
import FormikMultiCombobox from 'Components/fields/MultiComboBox';
import ErrorBoundary from 'Components/ErrorBoundary';
import pick from 'lodash/pick';
import useRequestParamsWithPagination from 'Hooks/useRequestParamsWithPagination';
import Breadcrumbs from 'Components/Breadcrumbs';

const statusOptions = Object.values(ComplianceStatusEnum);

export const filters = {
  idContains: {
    component: FormikTextInput,
    props: {
      label: 'ID / Name',
      placeholder: 'Enter part of an id or a name...',
    },
  },
  types: {
    component: FormikMultiCombobox,
    props: {
      items: RESOURCE_TYPES,
      label: 'Types',
      searchable: true,
      placeholder: 'Start typing resources...',
    },
  },
  integrationId: {
    component: FormikCombobox,
    props: {
      label: 'Source',
      searchable: true,
      items: [] as Array<Pick<ComplianceIntegration, 'integrationId' | 'integrationLabel'>>,
      itemToString: (integration: ComplianceIntegration) => integration.integrationLabel,
      placeholder: 'Choose a source...',
    },
  },
  complianceStatus: {
    component: FormikCombobox,
    props: {
      label: 'Status',
      itemToString: (status: ComplianceStatusEnum) => capitalize(status.toLowerCase()),
      items: statusOptions,
      placeholder: 'Choose a status...',
    },
  },
};

// The values of the filters that the resources page will show
export type ListResourcesFiltersValues = Pick<
  ListResourcesInput,
  'types' | 'complianceStatus' | 'idContains' | 'integrationId'
>;

// we mutate the shape of the integrationID here since we want it to have a different shape, that's
// dependant on the response of another API
type MutatedListResourcesFiltersValues = Omit<ListResourcesFiltersValues, 'integrationId'> & {
  integrationId: Pick<ComplianceIntegration, 'integrationId' | 'integrationLabel'>;
};

interface ListResourcesFiltersProps {
  onCancel: () => void;
  onSubmit: (values: ListResourcesFiltersValues) => void;
  initialValues: ListResourcesFiltersValues;
}

const ListResourcesActions: React.FC = () => {
  const [areFiltersVisible, setFiltersVisibility] = React.useState(false);
  const { requestParams, updateRequestParamsAndResetPaging } = useRequestParamsWithPagination<
    ListResourcesInput
  >();

  const { error, data } = useListComplianceSourceNames();

  if (data) {
    filters.integrationId.props.items = data.listComplianceIntegrations;
  }

  // Just because the `integrationId` field has objects as items, when a value is selected we have
  // an object of the shape {integrationId,integrationLabel} selected in our form. We need to
  // convert that back to integrationId so that the `onSubmit` given as prop to this component can
  // get the value it should expect
  const handleFiltersSubmit = React.useCallback(
    ({ integrationId: integrationObj, ...values }: MutatedListResourcesFiltersValues) => {
      updateRequestParamsAndResetPaging({
        ...values,
        integrationId: integrationObj ? integrationObj.integrationId : null,
      });
    },
    []
  );

  // Mutate initial values since the initial values provide an `integrationId` and we want to map
  // that to an `ComplianceIntegration` object, since that is the kind of items that the MultiCombobox has
  const filterKeys = Object.keys(filters) as (keyof ListResourcesFiltersValues)[];
  const filtersCount = filterKeys.filter(key => key in requestParams).length;

  // If there is at least one filter set visibility to true
  React.useEffect(() => {
    if (filtersCount > 0) {
      setFiltersVisibility(true);
    }
  }, [filtersCount]);

  const mutatedInitialValues = React.useMemo(
    () => ({
      ...(pick(requestParams, filterKeys) as ListResourcesFiltersValues),
      integrationId:
        data?.listComplianceIntegrations.find(
          i => i.integrationId === requestParams.integrationId
        ) || null,
    }),
    [requestParams, data]
  );

  return (
    <React.Fragment>
      {error && <Alert variant="error" title="Failed to fetch available sources" discardable />}
      <Breadcrumbs.Actions>
        <Flex justify="flex-end">
          <Button
            icon="filter"
            variant="outline"
            variantColor="navyblue"
            onClick={() => setFiltersVisibility(!areFiltersVisible)}
          >
            Filter Options {filtersCount ? `(${filtersCount})` : ''}
          </Button>
        </Flex>
      </Breadcrumbs.Actions>
      <Collapse open={areFiltersVisible}>
        <Box pb={6} as="section">
          <Card p={8}>
            <ErrorBoundary>
              <GenerateFiltersGroup<MutatedListResourcesFiltersValues>
                filters={filters}
                onSubmit={handleFiltersSubmit}
                initialValues={mutatedInitialValues}
              />
            </ErrorBoundary>
          </Card>
        </Box>
      </Collapse>
    </React.Fragment>
  );
};

export default React.memo(ListResourcesActions);
