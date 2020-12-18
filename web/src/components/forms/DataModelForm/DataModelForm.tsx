import React from 'react';
import { Flex, Tabs, Box, TabList, TabPanels, TabPanel, Card } from 'pouncejs';
import * as Yup from 'yup';
import { Formik, Form } from 'formik';
import { DataModelMapping } from 'Generated/schema';
import Breadcrumbs from 'Components/Breadcrumbs';
import LinkButton from 'Components/buttons/LinkButton';
import SubmitButton from 'Components/buttons/SubmitButton';
import urls from 'Source/urls';
import { BorderedTab, BorderTabDivider } from 'Components/BorderedTab';
import SettingsTabPanel from './SettingsTabPanel';
import DataModelMappingsTabPanel from './DataModelMappingsTabPanel';

export interface DataModelFormValues {
  displayName: string;
  id: string;
  enabled: boolean;
  logType: string;
  mappings: DataModelMapping[];
  body?: string;
}

export interface DataModelFormProps {
  initialValues: DataModelFormValues;
  onSubmit: (values: DataModelFormValues) => Promise<any>;
}

const validationSchema = Yup.object<DataModelFormValues>({
  displayName: Yup.string().required(),
  id: Yup.string().required(),
  enabled: Yup.boolean().required(),
  logType: Yup.string().required(),
  mappings: Yup.array<DataModelMapping>()
    .of(
      Yup.object().shape<DataModelMapping>(
        {
          name: Yup.string().required(),
          method: Yup.string()
            .test('mutex', "You shouldn't provide both a path & method", function (method) {
              return !this.parent.path || !method;
            })
            .when('path', {
              is: path => !path,
              then: Yup.string().required('Either a path or a method must be specified'),
              otherwise: Yup.string(),
            }),
          path: Yup.string()
            .test('mutex', "You shouldn't provide both a path & method", function (path) {
              return !this.parent.method || !path;
            })
            .when('method', {
              is: method => !method,
              then: Yup.string().required('Either a path or a method must be specified'),
              otherwise: Yup.string(),
            }),
        },
        [['method', 'path']]
      )
    )
    .required(),
  body: Yup.string(),
});

const DataModelForm: React.FC<DataModelFormProps> = ({ initialValues, onSubmit }) => {
  return (
    <Card position="relative">
      <Formik<DataModelFormValues>
        initialValues={initialValues}
        onSubmit={onSubmit}
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
