import React from 'react';
import { Box, Card, Link, Text } from 'pouncejs';
import BulkUploaderWizard from 'Components/wizards/BulkUploaderWizard';
import { ANALYSIS_UPLOAD_DOC_URL } from 'Source/constants';
import withSEO from 'Hoc/withSEO';

const BulkUploader = () => {
  return (
    <>
      <Card as="section" width={1} mb={6}>
        <BulkUploaderWizard />
      </Card>
      <Box>
        <Text fontSize="medium">
          You can find a detailed description of the process in our{' '}
          <Link external href={ANALYSIS_UPLOAD_DOC_URL}>
            designated docs page
          </Link>
          .
        </Text>
      </Box>
    </>
  );
};

export default withSEO({ title: 'Global Python Modules' })(BulkUploader);
