import React from 'react';
import { Box, Button, Card, Flex, Heading, IconButton, Text } from 'pouncejs';
import type { YAMLException } from 'js-yaml';
import { FastField, useFormikContext } from 'formik';
import FormikEditor from 'Components/fields/Editor';
import { DataModelFormValues } from '../DataModelForm';

const DataModelMappingsTabPanel: React.FC = () => {
  const { initialValues, values: { mappings } } = useFormikContext<DataModelFormValues>(); // prettier-ignore
  const [isYamlEditorOpen, setYamlEditorVisibility] = React.useState(true);
  const [isPythonEditorOpen, setPythonEditorVisibility] = React.useState(!!initialValues.body);
  const [yamlError, setYamlError] = React.useState<YAMLException>();

  const handleYamlValidation = React.useCallback(async () => {
    import(/* webpackChunkName: "js-yaml" */ 'js-yaml').then(({ default: yaml }) => {
      try {
        yaml.load(mappings);
      } catch (err) {
        const castedError = err as YAMLException;
        setYamlError({ name: castedError.name, message: castedError.message });
      }
    });
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
          <Heading size="x-small">YAML Function</Heading>
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
              aria-describedby={yamlError ? 'yaml-errors' : undefined}
              required
            />
            {yamlError && (
              <Flex
                p={4}
                borderRadius="medium"
                backgroundColor="pink-700"
                fontSize="medium"
                id="yaml-errors"
              >
                <Box as="b">{yamlError.name}: </Box>
                <Text fontStyle="italic" ml={1}>
                  {yamlError.message}
                </Text>
              </Flex>
            )}
            <Button
              variantColor="teal"
              icon="play"
              disabled={!mappings}
              onClick={handleYamlValidation}
            >
              Validate Syntax
            </Button>
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
