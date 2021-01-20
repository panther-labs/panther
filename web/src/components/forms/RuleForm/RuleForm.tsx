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
import { AddRuleInput, DetectionTestDefinition, UpdateRuleInput } from 'Generated/schema';
import * as Yup from 'yup';
import useUrlParams from 'Hooks/useUrlParams';
import { Button, Card, Flex, Box, TabList, TabPanel, TabPanels, Tabs } from 'pouncejs';
import { BorderedTab, BorderTabDivider } from 'Components/BorderedTab';
import invert from 'lodash/invert';
import ErrorBoundary from 'Components/ErrorBoundary';
import Breadcrumbs from 'Components/Breadcrumbs';
import SaveButton from 'Components/buttons/SaveButton';
import { BaseDetectionFormEditorSection } from 'Components/forms/BaseDetectionForm';
import { Form, Formik } from 'formik';
import FormSessionRestoration from 'Components/utils/FormSessionRestoration';
import useRouter from 'Hooks/useRouter';
import RuleFormTestSection from './RuleFormTestSection';
import RuleFormCoreSection from './RuleFormCoreSection';

// The validation checks that Formik will run
const validationSchema = Yup.object().shape({
  id: Yup.string().required(),
  body: Yup.string().required(),
  severity: Yup.string().required(),
  dedupPeriodMinutes: Yup.number().integer(),
  threshold: Yup.number().integer().moreThan(0).required(),
  logTypes: Yup.array().of(Yup.string()).required(),
  tests: Yup.array<DetectionTestDefinition>().of(
    Yup.object().shape({
      name: Yup.string().required(),
      expectedResult: Yup.boolean().required(),
      resource: Yup.string().required(),
    })
  ),
});

export interface RuleFormUrlParams {
  section?: 'settings' | 'functions';
}

const sectionToTabIndex: Record<RuleFormUrlParams['section'], number> = {
  settings: 0,
  functions: 1,
};

const tabIndexToSection = invert(sectionToTabIndex) as Record<number, RuleFormUrlParams['section']>;

export type RuleFormValues = Required<AddRuleInput> | Required<UpdateRuleInput>;
export type RuleFormProps = {
  /** The initial values of the form */
  initialValues: RuleFormValues;

  /** callback for the submission of the form */
  onSubmit: (values: RuleFormValues) => void;
};

const RuleForm: React.FC<RuleFormProps> = ({ initialValues, onSubmit }) => {
  const { history } = useRouter();
  const { urlParams, updateUrlParams } = useUrlParams<RuleFormUrlParams>();

  return (
    <Card position="relative">
      <Formik<RuleFormValues>
        initialValues={initialValues}
        onSubmit={onSubmit}
        enableReinitialize
        validationSchema={validationSchema}
      >
        <FormSessionRestoration sessionId={`rule-form-${initialValues.id || 'create'}`}>
          {({ clearFormSession }) => (
            <Form>
              <Breadcrumbs.Actions>
                <Flex spacing={4} justify="flex-end">
                  <Button
                    variantColor="darkgray"
                    icon="close-outline"
                    aria-label="Cancel Rule editing"
                    onClick={() => {
                      clearFormSession();
                      history.goBack();
                    }}
                  >
                    Cancel
                  </Button>
                  <SaveButton>{initialValues.id ? 'Update' : 'Save'}</SaveButton>
                </Flex>
              </Breadcrumbs.Actions>
              <Tabs
                index={sectionToTabIndex[urlParams.section] || 0}
                onChange={index => updateUrlParams({ section: tabIndexToSection[index] })}
              >
                <Box px={2}>
                  <TabList>
                    <BorderedTab>Rule Settings</BorderedTab>
                    <BorderedTab>Functions & Tests</BorderedTab>
                  </TabList>
                </Box>

                <BorderTabDivider />
                <Box p={6}>
                  <TabPanels>
                    <TabPanel data-testid="rule-settings-tabpanel" lazy>
                      <ErrorBoundary>
                        <RuleFormCoreSection />
                      </ErrorBoundary>
                    </TabPanel>
                    <TabPanel data-testid="function-settings-tabpanel" lazy>
                      <Flex spacing="6" direction="column">
                        <ErrorBoundary>
                          <BaseDetectionFormEditorSection type="rule" />
                        </ErrorBoundary>
                        <ErrorBoundary>
                          <RuleFormTestSection />
                        </ErrorBoundary>
                      </Flex>
                    </TabPanel>
                  </TabPanels>
                </Box>
              </Tabs>
            </Form>
          )}
        </FormSessionRestoration>
      </Formik>
    </Card>
  );
};

export default RuleForm;
