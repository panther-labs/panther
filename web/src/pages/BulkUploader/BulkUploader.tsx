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
