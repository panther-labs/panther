import React from 'react';
import { Flex, Button, Tabs, Box, TabList, TabPanels, TabPanel, Card } from 'pouncejs';
import * as Yup from 'yup';
import { Formik, Form } from 'formik';
import Breadcrumbs from 'Components/Breadcrumbs';
import LinkButton from 'Components/buttons/LinkButton';
import urls from 'Source/urls';
import { BorderedTab, BorderTabDivider } from 'Components/BorderedTab';
import SettingsTabPanel from './SettingsTabPanel';
import DataModelMappingsTabPanel from './DataModelMappingsTabPanel';

export interface DataModelFormValues {
  displayName: string;
  id: string;
  enabled: boolean;
  logTypes: string[];
  mappings: string;
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
  logTypes: Yup.array().of(Yup.string()).required(),
  mappings: Yup.string().required(),
  body: Yup.string(),
});

const DataModelForm: React.FC<DataModelFormProps> = ({ initialValues, onSubmit }) => {
  return (
    <React.Fragment>
      <Breadcrumbs.Actions>
        <Flex justify="flex-end" spacing={4}>
          <LinkButton
            icon="close-circle"
            variantColor="darkgray"
            to={urls.logAnalysis.dataModels.list()}
          >
            Cancel
          </LinkButton>
          <Button icon="check-outline" variantColor="green">
            Save
          </Button>
        </Flex>
      </Breadcrumbs.Actions>
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
          </Form>
        </Formik>
      </Card>
    </React.Fragment>
  );
};

export default DataModelForm;
