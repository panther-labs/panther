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
import { AbstractButton, Box, Collapse, FormHelperText, SimpleGrid } from 'pouncejs';
import { DestinationConfigInput } from 'Generated/schema';
import BaseDestinationForm, {
  BaseDestinationFormValues,
  defaultValidationSchema,
} from 'Components/forms/BaseDestinationForm';
import JsonViewer from 'Components/JsonViewer';
import { pantherConfig } from 'Source/config';

type SQSFieldValues = Pick<DestinationConfigInput, 'sqs'>;

interface SQSDestinationFormProps {
  initialValues: BaseDestinationFormValues<SQSFieldValues>;
  onSubmit: (values: BaseDestinationFormValues<SQSFieldValues>) => void;
}

const sqsFieldsValidationSchema = Yup.object().shape({
  outputConfig: Yup.object().shape({
    sqs: Yup.object().shape({
      queueUrl: Yup.string().url('Queue URL must be a valid url').required('Queue URL is required'),
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
        AWS: `arn:aws:iam::${pantherConfig.AWS_ACCOUNT_ID}:root`,
      },
      Resource: '<Destination-SQS-Queue-ARN>',
    },
  ],
};

// We merge the two schemas together: the one deriving from the common fields, plus the custom
// ones that change for each destination.
// https://github.com/jquense/yup/issues/522
const mergedValidationSchema = defaultValidationSchema.concat(sqsFieldsValidationSchema);

const SqsDestinationForm: React.FC<SQSDestinationFormProps> = ({ onSubmit, initialValues }) => {
  const [showPolicy, setShowPolicy] = React.useState(false);

  return (
    <BaseDestinationForm<SQSFieldValues>
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
        <Box as="fieldset">
          <Field
            as={FormikTextInput}
            name="outputConfig.sqs.queueUrl"
            label="Queue URL"
            placeholder="Where should we send the queue data to?"
            required
            aria-describedby="queueUrl-label queueUrl-policy"
          />
          <FormHelperText id="queueUrl-label" mt={2}>
            <b>Note</b>: You would need to allow Panther <b>sqs:SendMessage</b> access to send alert
            messages to your queue.{' '}
            {!showPolicy && (
              <AbstractButton color="blue-400" onClick={() => setShowPolicy(true)}>
                Show Policy
              </AbstractButton>
            )}
          </FormHelperText>
          <Collapse open={showPolicy}>
            <Box my={4} id="queueUrl-policy">
              <JsonViewer data={SQS_QUEUE_POLICY} collapsed={false} />
            </Box>
          </Collapse>
        </Box>
      </SimpleGrid>
    </BaseDestinationForm>
  );
};

export default SqsDestinationForm;
