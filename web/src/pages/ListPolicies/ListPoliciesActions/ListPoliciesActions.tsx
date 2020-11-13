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
import urls from 'Source/urls';
import { RESOURCE_TYPES } from 'Source/constants';
import { ComplianceStatusEnum, SeverityEnum, ListPoliciesInput } from 'Generated/schema';
import GenerateFiltersGroup from 'Components/utils/GenerateFiltersGroup';
import { capitalize } from 'Helpers/utils';
import FormikTextInput from 'Components/fields/TextInput';
import FormikCombobox from 'Components/fields/ComboBox';
import FormikMultiCombobox from 'Components/fields/MultiComboBox';
import useRequestParamsWithPagination from 'Hooks/useRequestParamsWithPagination';
import { Box, Button, Card, Collapse, Flex } from 'pouncejs';
import ErrorBoundary from 'Components/ErrorBoundary';
import pick from 'lodash/pick';
import Breadcrumbs from 'Components/Breadcrumbs';
import LinkButton from 'Components/buttons/LinkButton';

const severityOptions = Object.values(SeverityEnum);
const statusOptions = Object.values(ComplianceStatusEnum);

export const filters = {
  nameContains: {
    component: FormikTextInput,
    props: {
      label: 'Name contains',
      placeholder: 'Enter a policy name...',
    },
  },
  resourceTypes: {
    component: FormikMultiCombobox,
    props: {
      searchable: true,
      items: RESOURCE_TYPES,
      label: 'Resource Types',
      placeholder: 'Start typing resources...',
    },
  },
  tags: {
    component: FormikMultiCombobox,
    props: {
      label: 'Tags',
      searchable: true,
      allowAdditions: true,
      items: [] as string[],
      placeholder: 'Filter with tags...',
    },
  },
  severity: {
    component: FormikCombobox,
    props: {
      label: 'Severity',
      items: ['', ...severityOptions],
      itemToString: (severity: SeverityEnum | '') =>
        severity === '' ? 'All' : capitalize(severity.toLowerCase()),
      placeholder: 'Choose a severity...',
    },
  },
  complianceStatus: {
    component: FormikCombobox,
    props: {
      label: 'Status',
      items: ['', ...statusOptions],
      itemToString: (status: ComplianceStatusEnum | '') =>
        status === '' ? 'All' : capitalize(status.toLowerCase()),
      placeholder: 'Choose a status...',
    },
  },
  enabled: {
    component: FormikCombobox,
    props: {
      label: 'Enabled',
      items: ['', true, false],
      itemToString: (item: boolean | string) => {
        if (item === '') {
          return 'All Policies';
        }
        return item === true ? 'Enabled Policies' : 'Disabled Policies';
      },
      placeholder: 'Show only enabled?',
    },
  },
  hasRemediation: {
    component: FormikCombobox,
    props: {
      label: 'Auto-remediation Status',
      items: ['', true, false],
      itemToString: (item: boolean | string) => {
        if (item === '') {
          return 'All';
        }
        return item === true ? 'Configured' : 'Not Configured';
      },
      placeholder: 'Choose a status...',
    },
  },
};

export type ListPoliciesFiltersValues = Pick<
  ListPoliciesInput,
  'complianceStatus' | 'tags' | 'severity' | 'resourceTypes' | 'nameContains' | 'enabled'
>;

const ListPoliciesActions: React.FC = () => {
  const [areFiltersVisible, setFiltersVisibility] = React.useState(false);
  const { requestParams, updateRequestParamsAndResetPaging } = useRequestParamsWithPagination<
    ListPoliciesInput
  >();

  const filterKeys = Object.keys(filters) as (keyof ListPoliciesInput)[];
  const filtersCount = filterKeys.filter(key => key in requestParams).length;

  // If there is at least one filter set visibility to true
  React.useEffect(() => {
    if (filtersCount > 0) {
      setFiltersVisibility(true);
    }
  }, [filtersCount]);

  // The initial filter values for when the filters component first renders. If you see down below,
  // we mount and unmount it depending on whether it's visible or not
  const initialFilterValues = React.useMemo(
    () => pick(requestParams, filterKeys) as ListPoliciesFiltersValues,
    [requestParams]
  );

  return (
    <React.Fragment>
      <Breadcrumbs.Actions>
        <Flex spacing={5} justify="flex-end">
          <Button
            active={areFiltersVisible}
            icon="filter"
            variant="outline"
            variantColor="navyblue"
            onClick={() => setFiltersVisibility(!areFiltersVisible)}
          >
            Filter Options {filtersCount ? `(${filtersCount})` : ''}
          </Button>
          <LinkButton to={urls.compliance.policies.create()}>Create New Policy</LinkButton>
        </Flex>
      </Breadcrumbs.Actions>
      <Collapse open={areFiltersVisible}>
        <Box pb={6} as="section">
          <Card p={8}>
            <ErrorBoundary>
              <GenerateFiltersGroup<ListPoliciesFiltersValues>
                filters={filters}
                onSubmit={updateRequestParamsAndResetPaging}
                initialValues={initialFilterValues}
              />
            </ErrorBoundary>
          </Card>
        </Box>
      </Collapse>
    </React.Fragment>
  );
};

export default React.memo(ListPoliciesActions);
