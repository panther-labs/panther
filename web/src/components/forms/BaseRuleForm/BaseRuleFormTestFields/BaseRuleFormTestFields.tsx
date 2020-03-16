/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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

import React, { MouseEvent } from 'react';
import { AnalysisTypeEnum, PolicyUnitTest } from 'Generated/schema';
import { FieldArray, FastField as Field, useFormikContext } from 'formik';
import {
  Button,
  Flex,
  Icon,
  InputElementLabel,
  Box,
  Tab,
  TabList,
  TabPanel,
  Alert,
} from 'pouncejs';
import { LOG_TYPES, RESOURCE_TYPES } from 'Source/constants';
import { formatJSON, extractErrorMessage } from 'Helpers/utils';
import FormikTextInput from 'Components/fields/TextInput';
import FormikEditor from 'Components/fields/Editor';
import FormikCombobox from 'Components/fields/ComboBox';
import FormikRadio from 'Components/fields/Radio';
import { PolicyFormValues } from 'Components/forms/PolicyForm';
import { RuleFormValues } from 'Components/forms/RuleForm';
import PolicyFormTestResultList from '../BaseRuleFormTestResultList';
import { useTestPolicy } from './graphql/testPolicy.generated';

type MandatoryFormFields = Pick<RuleFormValues, 'body' | 'tests'>;
type FormFields = MandatoryFormFields &
  Pick<RuleFormValues, 'logTypes'> &
  Pick<PolicyFormValues, 'resourceTypes'>;

const BaseRuleFormTestFields: React.FC = () => {
  // Read the values from the "parent" form. We expect a formik to be declared in the upper scope
  // since this is a "partial" form. If no Formik context is found this will error out intentionally
  const {
    values: { tests, resourceTypes, logTypes, body },
    validateForm,
  } = useFormikContext<FormFields>();
  const isPolicy = resourceTypes !== undefined;

  // Controls which test is the active test at the moment through a simple index variable
  const [activeTabIndex, setActiveTabIndex] = React.useState(0);

  // We want to keep a global reference on the number of tests created (regardless of the ones
  // deleted) so that we can give a proper serial number to each new test. This protects us against
  // bugs when it comes to naming tests like "Test 1", "Test 2", etc.
  const testsCreated = React.useRef(tests.length);

  // Load the mutation that will perform the policy testing but we are not yet populating it with
  // the variables since we'll do that on "click" - time
  // prettier-ignore
  const [testPolicy, { error, loading, data }] = useTestPolicy()

  // Helper function where the only thing parameterised is the array of tests to submit to the server
  // This helps us reduce the amount of code we write when the only thing changing is the number of
  // tests to run
  const runTests = (testsToRun: PolicyUnitTest[]) => {
    testPolicy({
      variables: {
        input: {
          body,
          resourceTypes: isPolicy ? resourceTypes : logTypes,
          analysisType: isPolicy ? AnalysisTypeEnum.Policy : AnalysisTypeEnum.Rule,
          tests: testsToRun,
        },
      },
    });
  };

  const resourceTypeInputProps = React.useMemo(
    () => ({
      placeholder: `Select a ${isPolicy ? 'resource' : 'log'} type to test`,
    }),
    [isPolicy]
  );

  // The field array below gets registered to the upper formik
  const testsCount = tests.length;
  return (
    <section>
      <InputElementLabel htmlFor="enabled">Test Record</InputElementLabel>
      <Box mt={6}>
        <FieldArray
          name="tests"
          render={arrayHelpers => {
            /**
             *
             * handler for when the user clicks to add a new test
             *
             */
            const handleTestAddition = () => {
              // increase the number of tests created
              testsCreated.current += 1;

              // adds a test
              arrayHelpers.push({
                name: `Test ${testsCreated.current}`,
                expectedResult: true,
                resource: formatJSON({}),
                resourceType: isPolicy ? RESOURCE_TYPES[0] : LOG_TYPES[0],
              });

              // focuses on the newly created test
              setActiveTabIndex(testsCount);
            };

            /**
             *
             * handler for when the user clicks to remove an existing test
             *
             */
            const handleTestRemoval = (e: MouseEvent, index: number) => {
              // the button is part of the "Tab" so we don't want to "navigate" to this tab
              // but only close it. Thus, we can't let the click event propagate.
              e.stopPropagation();

              // If we are removing an item that's to the "left" of the currently active one,
              // we will need to also move the `activeIndex` to the "left" by 1 tab
              if (index <= activeTabIndex) {
                setActiveTabIndex(index > 0 ? index - 1 : 0);
              }

              // removes the test
              arrayHelpers.remove(index);

              // There is currently a bug with Formik v2 and removing an item causes a wrong
              // `errors` state to be present. We manually kick in validation to fix that.
              // https://github.com/jaredpalmer/formik/issues/1616
              setTimeout(validateForm, 200);
            };

            return (
              <Box>
                <TabList>
                  {tests.map((test, index) => (
                    <Tab
                      key={test.name}
                      selected={activeTabIndex === index}
                      onSelect={() => setActiveTabIndex(index)}
                      id={test.name}
                      aria-controls={`panel-${test.name}`}
                      mr={4}
                      mb={4}
                      minWidth={250}
                    >
                      <Flex alignItems="center">
                        {test.name}
                        <Box ml="auto" mr={0} pl={3} onClick={e => handleTestRemoval(e, index)}>
                          <Icon type="remove" size="large" color="grey300" />
                        </Box>
                      </Flex>
                    </Tab>
                  ))}
                  <li>
                    <Button
                      type="button"
                      size="large"
                      variant="default"
                      mb={4}
                      onClick={handleTestAddition}
                    >
                      <Flex alignItems="center">
                        <Icon size="small" type="add" mr={2} />
                        Create {!testsCount ? 'your first' : ''} test
                      </Flex>
                    </Button>
                  </li>
                </TabList>
                {testsCount > 0 && (
                  <TabPanel selected aria-labelledby={tests[activeTabIndex].name}>
                    <Flex
                      justifyContent="space-around"
                      py={3}
                      borderTop="1px solid"
                      borderBottom="1px solid"
                      borderColor="grey50"
                    >
                      <Flex mt={5}>
                        <InputElementLabel htmlFor="severity" mr={6}>
                          * Name
                        </InputElementLabel>
                        <Field
                          as={FormikTextInput}
                          name={`tests[${activeTabIndex}].name`}
                          placeholder="The name of your test"
                        />
                      </Flex>
                      <Flex mt={5}>
                        <InputElementLabel htmlFor="severity" mr={6}>
                          * {isPolicy ? 'Resource' : 'Log'} Type
                        </InputElementLabel>
                        <Field
                          as={FormikCombobox}
                          searchable
                          name={`tests[${activeTabIndex}].resourceType`}
                          items={isPolicy ? RESOURCE_TYPES : LOG_TYPES}
                          inputProps={resourceTypeInputProps}
                        />
                      </Flex>
                      <Box>
                        <Flex justifyContent="space-between" width={225}>
                          <InputElementLabel htmlFor="expected-result-true">
                            Evaluate to True
                          </InputElementLabel>
                          <Field
                            as={FormikRadio}
                            id="expected-result-true"
                            name={`tests[${activeTabIndex}].expectedResult`}
                            value={true}
                          />
                        </Flex>
                        <Flex justifyContent="space-between" width={225}>
                          <InputElementLabel htmlFor="expected-result-false">
                            Evaluate to False
                          </InputElementLabel>
                          <Field
                            as={FormikRadio}
                            id="expected-result-false"
                            name={`tests[${activeTabIndex}].expectedResult`}
                            value={false}
                          />
                        </Flex>
                      </Box>
                    </Flex>
                    <Box mt={10} hidden={!tests.length}>
                      <Field
                        disabled={true}
                        as={FormikEditor}
                        placeholder="# Enter a JSON object describing the resource to test against"
                        name={`tests[${activeTabIndex}].resource`}
                        width="100%"
                        minLines={20}
                        mode="json"
                      />
                    </Box>
                    {error && (
                      <Alert
                        variant="error"
                        title="Internal error during testing"
                        description={
                          extractErrorMessage(error) ||
                          "An unknown error occured and we couldn't run your tests"
                        }
                        mt={5}
                      />
                    )}
                    {(loading || data) && (
                      <Box mt={5}>
                        <PolicyFormTestResultList running={loading} results={data?.testPolicy} />
                      </Box>
                    )}
                    <Flex mt={5}>
                      <Button
                        type="button"
                        variant="default"
                        size="large"
                        mr={4}
                        onClick={() => runTests([tests[activeTabIndex]])}
                      >
                        <Flex alignItems="center">
                          <Icon type="play" size="small" mr={2} />
                          Run Test
                        </Flex>
                      </Button>
                      <Button
                        type="button"
                        variant="default"
                        size="large"
                        onClick={() => runTests(tests)}
                      >
                        <Flex alignItems="center">
                          <Icon type="play-all" size="small" mr={2} />
                          Run All
                        </Flex>
                      </Button>
                    </Flex>
                  </TabPanel>
                )}
              </Box>
            );
          }}
        />
      </Box>
    </section>
  );
};

export default BaseRuleFormTestFields;
