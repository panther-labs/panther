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
import { AddPolicyInput, DetectionTestDefinition, UpdatePolicyInput } from 'Generated/schema';
import * as Yup from 'yup';
import { Button, Flex, Box, Card, TabList, TabPanel, TabPanels, Tabs } from 'pouncejs';
import { BorderedTab, BorderTabDivider } from 'Components/BorderedTab';
import { Form, Formik } from 'formik';
import useRouter from 'Hooks/useRouter';
import useUrlParams from 'Hooks/useUrlParams';
import invert from 'lodash/invert';
import Breadcrumbs from 'Components/Breadcrumbs';
import SaveButton from 'Components/buttons/SaveButton';
import { BaseDetectionFormEditorSection } from 'Components/forms/BaseDetectionForm';
import ErrorBoundary from 'Components/ErrorBoundary';
import FormSessionRestoration from 'Components/utils/FormSessionRestoration';
import PolicyFormAutoRemediationSection from './PolicyFormAutoRemediationSection';
import PolicyFormTestSection from './PolicyFormTestSection';
import PolicyFormCoreSection from './PolicyFormCoreSection';

// The validation checks that Formik will run
const validationSchema = Yup.object().shape({
  id: Yup.string().required(),
  body: Yup.string().required(),
  severity: Yup.string().required(),
  tests: Yup.array<DetectionTestDefinition>().of(
    Yup.object().shape({
      name: Yup.string().required(),
      expectedResult: Yup.boolean().required(),
      resource: Yup.string().required(),
    })
  ),
});

export interface PolicyFormUrlParams {
  section?: 'settings' | 'functions' | 'remediation';
}

const sectionToTabIndex: Record<PolicyFormUrlParams['section'], number> = {
  settings: 0,
  functions: 1,
  remediation: 2,
};

const tabIndexToSection = invert(sectionToTabIndex) as Record<
  number,
  PolicyFormUrlParams['section']
>;

export type PolicyFormValues = Required<AddPolicyInput> | Required<UpdatePolicyInput>;
export type PolicyFormProps = {
  /** The initial values of the form */
  initialValues: PolicyFormValues;

  /** callback for the submission of the form */
  onSubmit: (values: PolicyFormValues) => void;
};

const PolicyForm: React.FC<PolicyFormProps> = ({ initialValues, onSubmit }) => {
  const { history } = useRouter();
  const { urlParams, updateUrlParams } = useUrlParams<PolicyFormUrlParams>();

  return (
    <Card position="relative">
      <Formik<PolicyFormValues>
        initialValues={initialValues}
        onSubmit={onSubmit}
        enableReinitialize
        validationSchema={validationSchema}
      >
        <FormSessionRestoration sessionId={`policy-form-${initialValues.id || 'create'}`}>
          {({ clearFormSession }) => (
            <Form>
              <Breadcrumbs.Actions>
                <Flex spacing={4} justify="flex-end">
                  <Button
                    variantColor="darkgray"
                    icon="close-outline"
                    aria-label="Cancel Policy editing"
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
                    <BorderedTab>Policy Settings</BorderedTab>
                    <BorderedTab>Functions & Tests</BorderedTab>
                    <BorderedTab>Auto Remediation</BorderedTab>
                  </TabList>
                </Box>

                <BorderTabDivider />
                <Box p={6}>
                  <TabPanels>
                    <TabPanel data-testid="policy-settings-tabpanel" lazy>
                      <ErrorBoundary>
                        <PolicyFormCoreSection />
                      </ErrorBoundary>
                    </TabPanel>
                    <TabPanel data-testid="policy-functions-tabpanel" lazy>
                      <Flex spacing="6" direction="column">
                        <ErrorBoundary>
                          <BaseDetectionFormEditorSection type="policy" />
                        </ErrorBoundary>
                        <ErrorBoundary>
                          <PolicyFormTestSection />
                        </ErrorBoundary>
                      </Flex>
                    </TabPanel>
                    <TabPanel data-testid="policy-auto-remediation" lazy>
                      <ErrorBoundary>
                        <PolicyFormAutoRemediationSection />
                      </ErrorBoundary>
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

export default PolicyForm;
