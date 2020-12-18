import React from 'react';
import { Grid, Flex, useSnackbar } from 'pouncejs';
import { Field } from 'formik';
import FormikTextInput from 'Components/fields/TextInput';
import FormikSwitch from 'Components/fields/Switch';
import FormikCombobox from 'Components/fields/ComboBox';
import { useListAvailableLogTypes } from 'Source/graphql/queries';

const SettingsTabPanel: React.FC = () => {
  const { pushSnackbar } = useSnackbar();
  const { data } = useListAvailableLogTypes({
    onError: () => pushSnackbar({ title: "Couldn't fetch your available log types" }),
  });

  return (
    <React.Fragment>
      <Grid templateColumns="8fr 6fr 3fr" gap={5} mb={4}>
        <Field
          as={FormikTextInput}
          label="Display Name"
          placeholder="A nickname for this data model"
          name="displayName"
          required
        />
        <Field
          as={FormikTextInput}
          label="ID"
          placeholder="An identifier for this data model"
          name="id"
          required
        />
        <Flex align="center">
          <Field as={FormikSwitch} name="enabled" label="Data Model Enabled" />
        </Flex>
      </Grid>
      <Field
        as={FormikCombobox}
        searchable
        label="Log Type"
        name="logType"
        items={data?.listAvailableLogTypes.logTypes ?? []}
        placeholder="Where should the rule appoly?"
      />
    </React.Fragment>
  );
};

export default SettingsTabPanel;
