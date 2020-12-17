import React from 'react';
import { Flex, Tabs, Box, TabList, TabPanels, TabPanel, Card, useSnackbar } from 'pouncejs';
import * as Yup from 'yup';
import { Formik, Form } from 'formik';
import { DataModelMapping } from 'Generated/schema';
import Breadcrumbs from 'Components/Breadcrumbs';
import LinkButton from 'Components/buttons/LinkButton';
import SubmitButton from 'Components/buttons/SubmitButton';
import urls from 'Source/urls';
import { convertToYaml } from 'Helpers/utils';
import { BorderedTab, BorderTabDivider } from 'Components/BorderedTab';
import SettingsTabPanel from './SettingsTabPanel';
import DataModelMappingsTabPanel from './DataModelMappingsTabPanel';
import { convertYamlToDataModelMappings } from './utils';

export interface DataModelFormValues {
  displayName: string;
  id: string;
  enabled: boolean;
  logTypes: string[];
  mappings: DataModelMapping[];
  body?: string;
}

export interface DataModelFormProps {
  initialValues: DataModelFormValues;
  onSubmit: (values: DataModelFormValues) => Promise<any>;
}

export type _DataModelFormValues = Omit<DataModelFormValues, 'mappings'> & {
  mappings: string;
};

const validationSchema = Yup.object<_DataModelFormValues>({
  displayName: Yup.string().required(),
  id: Yup.string().required(),
  enabled: Yup.boolean().required(),
  logTypes: Yup.array().of(Yup.string()).required(),
  mappings: Yup.string().required(),
  body: Yup.string(),
});

const DataModelForm: React.FC<DataModelFormProps> = ({
  initialValues: userFacingInitialValues,
  onSubmit,
}) => {
  const [initialValues, setInitialValues] = React.useState<_DataModelFormValues>({
    ...userFacingInitialValues,
    mappings: '',
  });
  const { pushSnackbar } = useSnackbar();

  React.useEffect(() => {
    (async () => {
      try {
        const mappings = await convertToYaml(userFacingInitialValues);
        setInitialValues({ ...initialValues, mappings });
      } catch (err) {
        // noop
      }
    })();
  }, [initialValues, userFacingInitialValues]);

  const handleSubmit = React.useCallback(
    async (values: _DataModelFormValues) => {
      try {
        const structuredMappings = await convertYamlToDataModelMappings(values.mappings);
        await onSubmit({ ...values, mappings: structuredMappings });
      } catch (err) {
        pushSnackbar({ variant: 'error', title: err.toString() });
      }
    },
    [onSubmit]
  );

  return (
    <Card position="relative">
      <Formik<_DataModelFormValues>
        initialValues={initialValues}
        onSubmit={handleSubmit}
        validationSchema={validationSchema}
      >
        <Form>
          <Tabs>
            <Box px={2}>
              <TabList>
                <BorderedTab>Settings</BorderedTab>
                <BorderedTab>Data Model Mappings</BorderedTab>
              </TabList>
              <BorderTabDivider />
              <Box p={6}>
                <TabPanels>
                  <TabPanel data-testid="settings-tabpanel">
                    <SettingsTabPanel />
                  </TabPanel>
                  <TabPanel data-testid="data-model-mappings-tabpanel" lazy unmountWhenInactive>
                    <DataModelMappingsTabPanel />
                  </TabPanel>
                </TabPanels>
              </Box>
            </Box>
          </Tabs>
          <Breadcrumbs.Actions>
            <Flex justify="flex-end" spacing={4}>
              <LinkButton
                icon="close-circle"
                variantColor="darkgray"
                to={urls.logAnalysis.dataModels.list()}
              >
                Cancel
              </LinkButton>
              <SubmitButton icon="check-outline" variantColor="green">
                Save
              </SubmitButton>
            </Flex>
          </Breadcrumbs.Actions>
        </Form>
      </Formik>
    </Card>
  );
};

export default DataModelForm;
