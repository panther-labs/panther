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
import { DetectionTestDefinition, DetectionTestDefinitionInput } from 'Generated/schema';
import { FieldArray, FastField as Field, useFormikContext } from 'formik';
import { Heading, Button, Flex, Icon, Grid, Box, AbstractButton, Card, IconButton } from 'pouncejs';
import { formatJSON, generateRandomColor } from 'Helpers/utils';
import FormikTextInput from 'Components/fields/TextInput';
import FormikEditor from 'Components/fields/Editor';
import FormikRadio from 'Components/fields/Radio';
import { PolicyFormValues } from 'Components/forms/PolicyForm';
import { RuleFormValues } from 'Components/forms/RuleForm';
import { MODALS } from 'Components/utils/Modal';
import useModal from 'Hooks/useModal';

interface BaseDetectionFormTestSectionProps {
  type: 'rule' | 'policy';
  runTests: (testsToRun: DetectionTestDefinition[]) => any;
  renderTestResults: React.ReactElement;
}

const BaseDetectionFormTestSection: React.FC<BaseDetectionFormTestSectionProps> = ({
  type,
  runTests,
  renderTestResults,
}) => {
  // Read the values from the "parent" form. We expect a formik to be declared in the upper scope
  // since this is a "partial" form. If no Formik context is found this will error out intentionally
  const {
    values: { tests },
    validateForm,
  } = useFormikContext<RuleFormValues | PolicyFormValues>();
  const { showModal } = useModal();
  const [open, setOpen] = React.useState(false);
  const [activeTabIndex, setActiveTabIndex] = React.useState(0);

  const testsCount = tests.length;
  const testsExist = testsCount > 0;

  React.useLayoutEffect(() => {
    setOpen(testsExist);
  }, [testsExist]);

  // The field array below gets registered to the upper formik
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
          const newTest: DetectionTestDefinitionInput = {
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
          <Card variant="dark" p={4}>
            <Flex spacing={4}>
              <Box mt={2}>
                <IconButton
                  variant="ghost"
                  variantColor="darkblue"
                  variantBorderStyle="circle"
                  active={open}
                  icon={open ? 'caret-up' : 'caret-down'}
                  onClick={() => setOpen(prev => !prev)}
                  size="medium"
                  aria-label="Toggle Tests visibility"
                />
              </Box>
              {testsExist ? (
                <Flex
                  as="ul"
                  wrap="wrap"
                  spacing={4}
                  flexGrow={1}
                  flexBasis={0}
                  mt={1}
                  mb={open ? 0 : -4}
                >
                  {tests.map((test, index) => (
                    <Box as="li" mb={4} key={test.name}>
                      <AbstractButton
                        borderRadius="pill"
                        px={4}
                        py={2}
                        backgroundColor={activeTabIndex === index ? 'blue-400' : 'navyblue-300'}
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
              ) : (
                <Heading as="h2" size="x-small" alignSelf="center" flexGrow={1} ml={0}>
                  Test
                </Heading>
              )}
              <Button icon="brackets" aria-label="Create test" onClick={handleTestAddition}>
                Create {!testsExist ? 'your first' : ''} test
              </Button>
            </Flex>
            {open && testsExist && (
              <React.Fragment>
                <Grid columnGap={5} templateColumns="1fr 2fr" mt={2} mb={6}>
                  <Field
                    as={FormikTextInput}
                    name={`tests[${activeTabIndex}].name`}
                    placeholder="The name of your test"
                    label="Name"
                  />
                  <Flex align="center" spacing={5}>
                    <Box fontSize="medium" fontWeight="medium" flexGrow={1} textAlign="right">
                      {type === 'policy'
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

                <Box mb={5}>
                  <Field
                    as={FormikEditor}
                    placeholder="# Enter a JSON object describing the resource to test against"
                    name={`tests[${activeTabIndex}].resource`}
                    width="100%"
                    minLines={20}
                    mode="json"
                  />
                </Box>
                {renderTestResults}
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
          </Card>
        );
      }}
    />
  );
};

export default React.memo(BaseDetectionFormTestSection);
