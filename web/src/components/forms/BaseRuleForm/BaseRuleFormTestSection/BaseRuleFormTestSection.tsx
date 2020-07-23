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

import React, { MouseEvent } from 'react';
import { AnalysisTypeEnum, PolicyUnitTest, PolicyUnitTestInput } from 'Generated/schema';
import { FieldArray, FastField as Field, useFormikContext } from 'formik';
import { Button, Flex, Icon, Grid, Box, Alert, AbstractButton } from 'pouncejs';
import { formatJSON, extractErrorMessage, generateRandomColor } from 'Helpers/utils';
import FormikTextInput from 'Components/fields/TextInput';
import FormikEditor from 'Components/fields/Editor';
import FormikRadio from 'Components/fields/Radio';
import { PolicyFormValues } from 'Components/forms/PolicyForm';
import { RuleFormValues } from 'Components/forms/RuleForm';
import { MODALS } from 'Components/utils/Modal';
import Panel from 'Components/Panel';
import useModal from 'Hooks/useModal';
import PolicyFormTestResultList from '../BaseRuleFormTestResultList';
import { useTestPolicy } from './graphql/testPolicy.generated';

type MandatoryFormFields = Pick<RuleFormValues, 'body' | 'tests'>;
type FormFields = MandatoryFormFields &
  Pick<RuleFormValues, 'logTypes'> &
  Pick<PolicyFormValues, 'resourceTypes'>;

const BaseRuleFormTestSection: React.FC = () => {
  // Read the values from the "parent" form. We expect a formik to be declared in the upper scope
  // since this is a "partial" form. If no Formik context is found this will error out intentionally
  const {
    values: { tests, resourceTypes, logTypes, body },
    validateForm,
  } = useFormikContext<FormFields>();
  const isPolicy = resourceTypes !== undefined;

  const { showModal } = useModal();

  // Controls which test is the active test at the moment through a simple index variable
  const [activeTabIndex, setActiveTabIndex] = React.useState(0);

  // Load the mutation that will perform the policy testing but we are not yet populating it with
  // the variables since we'll do that on "click" - time
  // prettier-ignore
  const [testPolicy, { error, loading, data }] = useTestPolicy();

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

  // The field array below gets registered to the upper formik
  const testsCount = tests.length;
  return (
    <FieldArray
      name="tests"
      render={arrayHelpers => {
        /**
         *
         * handler for when the user clicks to add a new test
         *
         */
        const handleTestAddition = () => {
          const newTest: PolicyUnitTestInput = {
            name: `Test-${generateRandomColor()}`,
            expectedResult: true,
            resource: formatJSON({}),
          };

          // adds a test
          arrayHelpers.push(newTest);

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

          showModal({
            modal: MODALS.DELETE_TEST,
            props: {
              test: tests[index],
              onConfirm: () => {
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
              },
            },
          });
        };

        return (
          <Panel
            title="Test Record"
            actions={
              <Button icon="add" onClick={handleTestAddition}>
                Create {!testsCount ? 'your first' : ''} test
              </Button>
            }
          >
            {testsCount > 0 && (
              <React.Fragment>
                <Flex wrap="wrap" as="ul">
                  {tests.map((test, index) => (
                    <Box as="li" mr={4} mb={4} key={test.name}>
                      <AbstractButton
                        borderRadius="pill"
                        px={4}
                        py={2}
                        bg={activeTabIndex === index ? 'blue-400' : 'navyblue-300'}
                        onClick={() => setActiveTabIndex(index)}
                      >
                        <Flex align="center">
                          {test.name}
                          <Icon
                            type="close"
                            size="x-small"
                            ml={6}
                            onClick={e => handleTestRemoval(e, index)}
                          />
                        </Flex>
                      </AbstractButton>
                    </Box>
                  ))}
                </Flex>
                <Grid columnGap={5} templateColumns="1fr 2fr" mt={2} mb={6}>
                  <Field
                    as={FormikTextInput}
                    name={`tests[${activeTabIndex}].name`}
                    placeholder="The name of your test"
                    label="Name"
                  />
                  <Flex align="center" spacing={5}>
                    <Box fontSize="medium" fontWeight="medium" flexGrow={1} textAlign="right">
                      {isPolicy
                        ? 'Test resource should be compliant'
                        : 'Test event should trigger an alert'}
                    </Box>
                    <Field
                      as={FormikRadio}
                      name={`tests[${activeTabIndex}].expectedResult`}
                      value={true}
                      label="Yes"
                    />
                    <Field
                      as={FormikRadio}
                      name={`tests[${activeTabIndex}].expectedResult`}
                      value={false}
                      label="No"
                    />
                  </Flex>
                </Grid>
                <Field
                  as={FormikEditor}
                  placeholder="# Enter a JSON object describing the resource to test against"
                  name={`tests[${activeTabIndex}].resource`}
                  width="100%"
                  minLines={20}
                  mode="json"
                />
                {error && (
                  <Box mt={5}>
                    <Alert
                      variant="error"
                      title="Internal error during testing"
                      description={
                        extractErrorMessage(error) ||
                        "An unknown error occured and we couldn't run your tests"
                      }
                    />
                  </Box>
                )}
                {(loading || data) && (
                  <Box mt={5}>
                    <PolicyFormTestResultList running={loading} results={data?.testPolicy} />
                  </Box>
                )}
                <Flex mt={5} spacing={4}>
                  <Button
                    variantColor="orange"
                    icon="play"
                    onClick={() => runTests([tests[activeTabIndex]])}
                  >
                    Run Test
                  </Button>
                  <Button variantColor="orange" icon="play-all" onClick={() => runTests(tests)}>
                    Run All
                  </Button>
                </Flex>
              </React.Fragment>
            )}
          </Panel>
        );
      }}
    />
  );
};

export default BaseRuleFormTestSection;
