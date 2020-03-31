/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
import { Box, Text } from 'pouncejs';
import { DestinationConfigInput } from 'Generated/schema';
import BaseDestinationForm, {
  BaseDestinationFormValues,
  defaultValidationSchema,
} from 'Components/forms/BaseDestinationForm';
import JsonViewer from 'Components/JsonViewer';

type SQSFieldValues = Pick<DestinationConfigInput, 'sqs'>;

interface SQSDestinationFormProps {
  initialValues: BaseDestinationFormValues<SQSFieldValues>;
  onSubmit: (values: BaseDestinationFormValues<SQSFieldValues>) => void;
}

const sqsFieldsValidationSchema = Yup.object().shape({
  outputConfig: Yup.object().shape({
    sqs: Yup.object().shape({
      queueUrl: Yup.string()
        .url('Queue URL must be a valid url')
        .required('Queue URL is required'),
    }),
  }),
});

const SQS_QUEUE_POLICY = {
  Version: '2012-10-17',
  Statement: [
    {
      Sid: 'AllowPantherToSendAlerts',
      Effect: 'Allow',
      Action: 'sqs:SendMessage',
      Principal: {
        AWS: `arn:aws:iam::${process.env.AWS_ACCOUNT_ID}:root`,
      },
      Resource: '<Destination-SQS-Queue-ARN>',
    },
  ],
};

// @ts-ignore
// We merge the two schemas together: the one deriving from the common fields, plus the custom
// ones that change for each destination.
// https://github.com/jquense/yup/issues/522
const mergedValidationSchema = defaultValidationSchema.concat(sqsFieldsValidationSchema);

const SqsDestinationForm: React.FC<SQSDestinationFormProps> = ({ onSubmit, initialValues }) => {
  return (
    <BaseDestinationForm<SQSFieldValues>
      initialValues={initialValues}
      validationSchema={mergedValidationSchema}
      onSubmit={onSubmit}
    >
      <Field
        as={FormikTextInput}
        name="outputConfig.sqs.queueUrl"
        label="Queue URL"
        placeholder="Where should we send the queue data to?"
        mb={2}
        aria-required
      />
      <Box mb={6}>
        <Text size="small" color="grey400" mb={2}>
          <b>Note</b>: You would need to allow Panther <b>sqs:SendMessage</b> access to send alert
          messages to your SQS queue
        </Text>
        <JsonViewer data={SQS_QUEUE_POLICY} collapsed={false} />
      </Box>
    </BaseDestinationForm>
  );
};

export default SqsDestinationForm;
