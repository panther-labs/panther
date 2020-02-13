import React from 'react';
import { Field } from 'formik';
import FormikCheckbox from 'Components/fields/checkbox';
import { Box, Flex, InputElementLabel, Text } from 'pouncejs';

const ErrorReportingSection: React.FC = () => {
  return (
    <Flex alignItems="flex-start" mb={10}>
      <Field as={FormikCheckbox} name="errorReportingConsent" id="errorReportingConsent" />
      <Box ml={2}>
        <InputElementLabel htmlFor="errorReportingConsent">
          Report web application errors
        </InputElementLabel>
        <Text color="grey300" size="medium">
          Crashes and runtime exceptions will be <b>anonymously</b> reported, in an effort to make
          the Panther team aware of the related issues
        </Text>
      </Box>
    </Flex>
  );
};

export default ErrorReportingSection;
