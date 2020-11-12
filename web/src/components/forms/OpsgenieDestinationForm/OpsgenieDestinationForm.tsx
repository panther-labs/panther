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

import React from 'react';
import { FastField, Field } from 'formik';
import * as Yup from 'yup';
import FormikTextInput from 'Components/fields/TextInput';
import SensitiveTextInput from 'Components/fields/SensitiveTextInput';
import { DestinationConfigInput, OpsgenieServiceRegionEnum } from 'Generated/schema';
import BaseDestinationForm, {
  BaseDestinationFormValues,
  defaultValidationSchema,
} from 'Components/forms/BaseDestinationForm';
import { Box, Flex, FormHelperText, SimpleGrid } from 'pouncejs';
import FormikRadio from 'Components/fields/Radio';

type OpsgenieFieldValues = Pick<DestinationConfigInput, 'opsgenie'>;
type RegionFieldName = {
  US: string;
  EU: string;
};
interface OpsgenieDestinationFormProps {
  initialValues: BaseDestinationFormValues<OpsgenieFieldValues>;
  onSubmit: (values: BaseDestinationFormValues<OpsgenieFieldValues>) => void;
}

const OpsgenieDestinationForm: React.FC<OpsgenieDestinationFormProps> = ({
  onSubmit,
  initialValues,
}) => {
  const [serviceRegion, setServiceRegion] = React.useState<OpsgenieServiceRegionEnum>(
    OpsgenieServiceRegionEnum.Eu
  );
  const [fieldNames, setFieldNames] = React.useState<RegionFieldName>({
    US: 'outputConfig.opsgenie.serviceRegion.US',
    EU: 'outputConfig.opsgenie.serviceRegion',
  });

  const existing = initialValues.outputId;

  const opsgenieFieldsValidationSchema = Yup.object().shape({
    outputConfig: Yup.object().shape({
      opsgenie: Yup.object().shape({
        apiKey: existing ? Yup.string() : Yup.string().required(),
        serviceRegion: Yup.string().required(),
      }),
    }),
  });
  const mergedValidationSchema = defaultValidationSchema.concat(opsgenieFieldsValidationSchema);

  const handleSelectChange = (region: OpsgenieServiceRegionEnum) => {
    setFieldNames(prevState => ({
      ...prevState,
      [region]: 'outputConfig.opsgenie.serviceRegion',
    }));
    setServiceRegion(region);
  };

  // console.log('fieldNames', fieldNames)
  // console.log('serviceRegion', serviceRegion)
  // console.log('initialValues', initialValues.outputConfig.opsgenie.serviceRegion)
  return (
    <BaseDestinationForm<OpsgenieFieldValues>
      initialValues={initialValues}
      validationSchema={mergedValidationSchema}
      onSubmit={onSubmit}
    >
      <SimpleGrid gap={5} columns={2}>
        <Field
          name="displayName"
          as={FormikTextInput}
          label="* Display Name"
          placeholder="How should we name this?"
          required
        />
        <Field
          as={SensitiveTextInput}
          shouldMask={!!existing}
          name="outputConfig.opsgenie.apiKey"
          label="Opsgenie API key"
          placeholder="What's your organization's Opsgenie API key?"
          required={!existing}
          autoComplete="new-password"
        />
        <Box fontSize="medium" fontWeight="medium" flexGrow={1} textAlign="left">
          <FormHelperText mt={2} id="serviceRegion-helper-text">
            Change this selection to EU if you are registered to Opsgenie Europe
            (app.eu.opsgenie.com).
          </FormHelperText>
        </Box>
        <Flex align="center" justify="space-between">
          <FastField
            key={'test1'}
            as={FormikRadio}
            name={fieldNames.US}
            onChange={() => handleSelectChange(OpsgenieServiceRegionEnum.Us)}
            // checked={selectedSupportRegion === OpsgenieServiceRegionEnum.Eu}
            value={serviceRegion}
            label="US Service Region"
            aria-describedby="serviceRegion-helper-text"
          />
          <FastField
            key={'test2'}
            as={FormikRadio}
            name={fieldNames.EU}
            onChange={() => handleSelectChange(OpsgenieServiceRegionEnum.Eu)}
            // checked={selectedSupportRegion === OpsgenieServiceRegionEnum.Eu}
            value={serviceRegion}
            label="EU Service Region"
            aria-describedby="serviceRegion-helper-text"
          />
        </Flex>
      </SimpleGrid>
    </BaseDestinationForm>
  );
};

export default OpsgenieDestinationForm;
