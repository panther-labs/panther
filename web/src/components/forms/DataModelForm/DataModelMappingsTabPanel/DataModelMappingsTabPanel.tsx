import React from 'react';
import { Box, Grid, Card, Flex, Heading, IconButton } from 'pouncejs';
import { FastField, Field, FieldArray, useFormikContext } from 'formik';
import FormikEditor from 'Components/fields/Editor';
import FormikTextInput from 'Components/fields/TextInput';
import { DataModelFormValues } from '../DataModelForm';

const DataModelMappingsTabPanel: React.FC = () => {
  const { initialValues, values } = useFormikContext<DataModelFormValues>();
  const [isPythonEditorOpen, setPythonEditorVisibility] = React.useState(!!initialValues.body);

  return (
    <React.Fragment>
      <Card as="section" variant="dark" p={4} mb={5}>
        <FieldArray
          name="mappings"
          render={arrayHelpers => {
            return (
              <Flex direction="column" spacing={4}>
                {values.mappings.map((mapping, index) => (
                  <Grid key={index} templateColumns="9fr 9fr 9fr 2fr" gap={4}>
                    <Field
                      as={FormikTextInput}
                      label="Name"
                      placeholder="The name of the unified data model field"
                      name={`mappings[${index}].name`}
                      required
                    />
                    <Field
                      as={FormikTextInput}
                      label="Field Path"
                      placeholder="The path to the log type field to map to"
                      name={`mappings[${index}].path`}
                    />
                    <Field
                      as={FormikTextInput}
                      label="Field Method"
                      placeholder="A log type method to map to"
                      name={`mappings[${index}].method`}
                    />
                    <Flex spacing={2} align="center">
                      {index > 0 && (
                        <IconButton
                          size="medium"
                          icon="close"
                          aria-label="Remove mapping"
                          onClick={() => arrayHelpers.remove(index)}
                        />
                      )}
                      {index === values.mappings.length - 1 && (
                        <IconButton
                          size="medium"
                          icon="add"
                          aria-label="Add a new mapping"
                          onClick={() => arrayHelpers.push({ name: '', method: '', path: '' })}
                        />
                      )}
                    </Flex>
                  </Grid>
                ))}
              </Flex>
            );
          }}
        />
      </Card>
      <Card as="section" variant="dark" p={4}>
        <Flex align="center" spacing={4}>
          <IconButton
            variant="ghost"
            active={isPythonEditorOpen}
            variantColor="navyblue"
            icon={isPythonEditorOpen ? 'caret-up' : 'caret-down'}
            onClick={() => setPythonEditorVisibility(v => !v)}
            size="medium"
            aria-label="Toggle Python Editor visibility"
          />
          <Heading size="x-small">
            Python Module <i>(optional)</i>
          </Heading>
        </Flex>
        {isPythonEditorOpen && (
          <Box mt={4}>
            <FastField
              as={FormikEditor}
              placeholder="# Enter the body of this mapping..."
              name="body"
              width="100%"
              minLines={10}
              mode="python"
            />
          </Box>
        )}
      </Card>
    </React.Fragment>
  );
};

export default DataModelMappingsTabPanel;
