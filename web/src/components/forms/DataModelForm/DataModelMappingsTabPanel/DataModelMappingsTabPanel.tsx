import React from 'react';
import { Box, Button, Card, Flex, Heading, IconButton, Text } from 'pouncejs';
import { parseYaml } from 'Helpers/utils';
import isEmpty from 'lodash/isEmpty';
import { FastField, useFormikContext } from 'formik';
import FormikEditor from 'Components/fields/Editor';
import { _DataModelFormValues } from '../DataModelForm';

const DataModelMappingsTabPanel: React.FC = () => {
  const { initialValues, values: { mappings } } = useFormikContext<_DataModelFormValues>(); // prettier-ignore
  const [isYamlEditorOpen, setYamlEditorVisibility] = React.useState(true);
  const [isPythonEditorOpen, setPythonEditorVisibility] = React.useState(!!initialValues.body);
  const [yamlErrors, setYamlErrors] = React.useState<Error[]>();

  const isYamlValid = yamlErrors && isEmpty(yamlErrors);
  const hasYamlErrors = yamlErrors && !isEmpty(yamlErrors);
  const userHasValidatedYaml = isYamlValid || hasYamlErrors;

  const handleYamlValidation = React.useCallback(async () => {
    try {
      await parseYaml(mappings);
      setYamlErrors([]);
    } catch (err) {
      setYamlErrors([err]);
    }
  }, [mappings]);

  return (
    <React.Fragment>
      <Card variant="dark" p={4} mb={4}>
        <Flex align="center" spacing={4}>
          <IconButton
            variant="ghost"
            active={isYamlEditorOpen}
            variantColor="navyblue"
            icon={isYamlEditorOpen ? 'caret-up' : 'caret-down'}
            onClick={() => setYamlEditorVisibility(v => !v)}
            size="medium"
            aria-label="Toggle YAML Editor visibility"
          />
          <Heading size="x-small">YAML Mappings</Heading>
        </Flex>
        {isYamlEditorOpen && (
          <Flex direction="column" spacing={4} mt={4}>
            <FastField
              as={FormikEditor}
              placeholder="# Enter the mappings for this data model"
              name="mappings"
              width="100%"
              minLines={10}
              mode="yaml"
              aria-describedby={hasYamlErrors ? 'yaml-errors' : undefined}
              required
            />
            {hasYamlErrors && (
              <Flex
                p={4}
                borderRadius="medium"
                backgroundColor="pink-700"
                fontSize="medium"
                id="yaml-errors"
              >
                <Box as="b">{yamlErrors[0].name}: </Box>
                <Text fontStyle="italic" ml={1}>
                  {yamlErrors[0].message}
                </Text>
              </Flex>
            )}
            {isYamlValid && (
              <Box
                p={4}
                borderRadius="medium"
                backgroundColor="green-500"
                fontSize="medium"
                fontWeight="bold"
              >
                Everything{"'"}s looking good
              </Box>
            )}
            <Box>
              <Button
                variantColor="teal"
                icon="play"
                disabled={!mappings}
                onClick={handleYamlValidation}
              >
                {userHasValidatedYaml ? 'Validate Syntax' : 'Validate Again'}
              </Button>
            </Box>
          </Flex>
        )}
      </Card>
      <Card variant="dark" p={4}>
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
