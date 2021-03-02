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
import { Field, Form, Formik } from 'formik';
import mapValues from 'lodash/mapValues';
import {
  Box,
  Button,
  Card,
  Flex,
  Popover,
  PopoverContent,
  PopoverTrigger,
  SimpleGrid,
} from 'pouncejs';
import {
  ComplianceStatusEnum,
  DetectionTypeEnum,
  ListDetectionsInput,
  SeverityEnum,
} from 'Generated/schema';
import useRequestParamsWithPagination from 'Hooks/useRequestParamsWithPagination';
import isUndefined from 'lodash/isUndefined';
import { capitalize } from 'Helpers/utils';
import TextButton from 'Components/buttons/TextButton';
import FormikCombobox from 'Components/fields/ComboBox';
import FormikMultiCombobox from 'Components/fields/MultiComboBox';
import { RESOURCE_TYPES } from 'Source/constants';
import { useListAvailableLogTypes } from 'Source/graphql/queries';

export type ListDetectionsDropdownFilterValues = Pick<
  ListDetectionsInput,
  | 'severity'
  | 'enabled'
  | 'hasRemediation'
  | 'analysisTypes'
  | 'complianceStatus'
  | 'initialSet'
  | 'logTypes'
  | 'resourceTypes'
  | 'tags'
>;

const ALL = 'ALL';

const severityFieldItems = Object.values(SeverityEnum);
const severityFieldItemToString = (severity: SeverityEnum) => capitalize(severity.toLowerCase());

const detectionTypeFieldItems = Object.values(DetectionTypeEnum);
const detectionFieldTypeItemToString = (item: DetectionTypeEnum) => capitalize(item.toLowerCase());

const enabledFieldItems = [ALL, true, false];
const enabledFieldItemToString = (item: boolean | typeof ALL) => {
  if (item === ALL) {
    return 'All';
  }
  return item === true ? 'Enabled' : 'Disabled';
};

const remediationFieldItems = [ALL, true, false];
const remediationFieldItemToString = (item: boolean | typeof ALL) => {
  if (item === ALL) {
    return 'All';
  }
  return item === true ? 'Configured' : 'Not Configured';
};

const creatorFieldItems = [ALL, true, false];
const creatorFieldItemToString = (item: boolean | typeof ALL) => {
  if (item === ALL) {
    return 'Any';
  }
  return item === true ? 'Panther (system)' : 'Me';
};

const complianceStatusFieldItems = [ALL, ...Object.values(ComplianceStatusEnum)];
const complianceStatusFieldItemToString = (status: ComplianceStatusEnum | typeof ALL) =>
  status === ALL ? 'All' : capitalize(status.toLowerCase());

const defaultDropdownValues = {
  enabled: null,
  complianceStatus: null,
  hasRemediation: null,
  initialSet: null,
  severity: [],
  logTypes: [],
  resourceTypes: [],
  tags: [],
  analysisTypes: [],
};

const DropdownFilters: React.FC = () => {
  const { data: logTypeData } = useListAvailableLogTypes();
  const { requestParams, updateRequestParamsAndResetPaging } = useRequestParamsWithPagination<
    ListDetectionsInput
  >();

  const initialDropdownFilters = React.useMemo(
    () =>
      ({
        ...defaultDropdownValues,
        ...requestParams,
      } as ListDetectionsDropdownFilterValues),
    [requestParams]
  );

  const handleSubmit = React.useCallback(
    (values: ListDetectionsDropdownFilterValues) => {
      // @ts-ignore `mapValues` has weird typings
      updateRequestParamsAndResetPaging(mapValues(values, v => (v === ALL ? null : v)));
    },
    [updateRequestParamsAndResetPaging]
  );

  const filtersCount = Object.keys(defaultDropdownValues).filter(
    key => !isUndefined(requestParams[key])
  ).length;

  return (
    <Popover>
      {({ close: closePopover }) => (
        <React.Fragment>
          <PopoverTrigger
            as={Button}
            iconAlignment="right"
            icon="filter-light"
            size="large"
            aria-label="Detection Options"
          >
            Filters {filtersCount ? `(${filtersCount})` : ''}
          </PopoverTrigger>
          <PopoverContent>
            <Card
              shadow="dark300"
              my={14}
              p={6}
              pb={4}
              backgroundColor="navyblue-400"
              minWidth={900}
              data-testid="dropdown-detections-listing-filters"
            >
              <Formik<ListDetectionsDropdownFilterValues>
                enableReinitialize
                onSubmit={handleSubmit}
                initialValues={initialDropdownFilters}
              >
                {({ setValues }) => (
                  <Form>
                    <Flex direction="column" spacing={4}>
                      <SimpleGrid columns={2} spacingX={4} spacingY={5}>
                        <Field
                          as={FormikMultiCombobox}
                          label="Detection Types"
                          name="analysisTypes"
                          placeholder="Select detection types"
                          items={detectionTypeFieldItems}
                          itemToString={detectionFieldTypeItemToString}
                        />
                        <Field
                          name="severity"
                          as={FormikMultiCombobox}
                          items={severityFieldItems}
                          itemToString={severityFieldItemToString}
                          label="Severities"
                          placeholder="Select severities to filter..."
                        />
                        <Field
                          as={FormikMultiCombobox}
                          searchable
                          label="Log Types"
                          name="logTypes"
                          items={logTypeData?.listAvailableLogTypes?.logTypes ?? []}
                          placeholder="Select log types to filter by..."
                        />
                        <Field
                          as={FormikMultiCombobox}
                          searchable
                          label="Resource Types"
                          name="resourceTypes"
                          items={RESOURCE_TYPES}
                          placeholder="Select resource types to filter by..."
                        />
                        <SimpleGrid columns={2} spacingX={5}>
                          <Field
                            as={FormikCombobox}
                            name="initialSet"
                            items={creatorFieldItems}
                            itemToString={creatorFieldItemToString}
                            label="Created by"
                            placeholder="Filter by detection creator..."
                          />
                          <Field
                            as={FormikCombobox}
                            name="complianceStatus"
                            items={complianceStatusFieldItems}
                            itemToString={complianceStatusFieldItemToString}
                            label="Policy Status"
                            placeholder="Filter by policy status..."
                          />
                        </SimpleGrid>
                        <SimpleGrid columns={2} spacingX={5}>
                          <Field
                            as={FormikCombobox}
                            name="hasRemediation"
                            items={remediationFieldItems}
                            itemToString={remediationFieldItemToString}
                            label="Remediation Status"
                            placeholder="Choose a remediation status...'"
                          />
                          <Field
                            as={FormikCombobox}
                            name="enabled"
                            items={enabledFieldItems}
                            itemToString={enabledFieldItemToString}
                            label="State"
                            placeholder="Which detections should we show?"
                          />
                        </SimpleGrid>
                      </SimpleGrid>
                      <Field
                        as={FormikMultiCombobox}
                        label="Tags"
                        searchable
                        allowAdditions
                        name="tags"
                        items={[]}
                        placeholder="Enter tags to filter by..."
                      />
                      <Flex direction="column" justify="center" align="center" spacing={4} my={2}>
                        <Box>
                          <Button type="submit" onClick={closePopover}>
                            Apply Filters
                          </Button>
                        </Box>
                        <TextButton role="button" onClick={() => setValues(defaultDropdownValues)}>
                          Clear Filters
                        </TextButton>
                      </Flex>
                    </Flex>
                  </Form>
                )}
              </Formik>
            </Card>
          </PopoverContent>
        </React.Fragment>
      )}
    </Popover>
  );
};

export default React.memo(DropdownFilters);
