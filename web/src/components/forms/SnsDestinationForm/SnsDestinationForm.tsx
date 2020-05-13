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
import { Field } from 'formik';
import * as Yup from 'yup';
import FormikTextInput from 'Components/fields/TextInput';
import { Text, Box } from 'pouncejs';
import { DestinationConfigInput } from 'Generated/schema';
import BaseDestinationForm, {
  BaseDestinationFormValues,
  defaultValidationSchema,
} from 'Components/forms/BaseDestinationForm';
import { pantherConfig } from 'Source/config';
import JsonViewer from 'Components/JsonViewer';
import { getArnRegexForService } from 'Helpers/utils';

const SNS_TOPIC_POLICY = {
  Version: '2012-10-17',
  Statement: [
    {
      Sid: 'AllowPantherToPublishAlerts',
      Effect: 'Allow',
      Action: 'sns:Publish',
      Principal: {
        AWS: `arn:aws:iam::${pantherConfig.AWS_ACCOUNT_ID}:root`,
      },
      Resource: '<Destination-SNS-Topic-ARN>',
    },
  ],
};

type SNSFieldValues = Pick<DestinationConfigInput, 'sns'>;

interface SNSDestinationFormProps {
  initialValues: BaseDestinationFormValues<SNSFieldValues>;
  onSubmit: (values: BaseDestinationFormValues<SNSFieldValues>) => void;
}

const snsFieldsValidationSchema = Yup.object().shape({
  outputConfig: Yup.object().shape({
    sns: Yup.object().shape({
      topicArn: Yup.string()
        .matches(getArnRegexForService('SNS'), 'Must be a valid SNS Topic')
        .required(),
    }),
  }),
});

// @ts-ignore
// We merge the two schemas together: the one deriving from the common fields, plus the custom
// ones that change for each destination.
// https://github.com/jquense/yup/issues/522
const mergedValidationSchema = defaultValidationSchema.concat(snsFieldsValidationSchema);

const SnsDestinationForm: React.FC<SNSDestinationFormProps> = ({ onSubmit, initialValues }) => {
  return (
    <BaseDestinationForm<SNSFieldValues>
      initialValues={initialValues}
      validationSchema={mergedValidationSchema}
      onSubmit={onSubmit}
    >
      <Field
        as={FormikTextInput}
        name="outputConfig.sns.topicArn"
        label="Topic ARN"
        placeholder="Where should we publish a notification to?"
        mb={2}
        aria-required
      />
      <Box mb={6}>
        <Text size="small" color="grey400" mb={2}>
          <b>Note</b>: You would need to allow Panther <b>sns:Publish</b> access to send alert
          messages to your SNS topic
        </Text>
        <JsonViewer data={SNS_TOPIC_POLICY} collapsed={false} />
      </Box>
    </BaseDestinationForm>
  );
};

export default SnsDestinationForm;
