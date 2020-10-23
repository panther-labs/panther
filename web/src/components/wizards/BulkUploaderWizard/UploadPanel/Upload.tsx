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
import { Box, Flex, Button, Img, Text } from 'pouncejs';
import Dropzone from 'react-dropzone';
import folderIllustration from 'Assets/illustrations/folder.svg';
import { WizardPanel } from 'Components/Wizard';

interface UploadProps {
  onFilesDropped: (acceptedFiles: File[]) => void;
}

const Upload: React.FC<UploadProps> = ({ onFilesDropped }) => {
  const [isDragged, setDrag] = React.useState(false);
  return (
    <>
      <WizardPanel.Heading
        title="Bulk Upload your rules, policies & python modules!"
        subtitle="If you have a collection of rules, policies, or python modules files, simply zip them together using any zip method you prefer and upload them here"
      />
      <Flex justify="center">
        <Dropzone
          multiple={false}
          onDragOver={() => setDrag(true)}
          onDragLeave={() => setDrag(false)}
          onDrop={onFilesDropped}
          accept="zip,application/octet-stream,application/zip,application/x-zip,application/x-zip-compressed"
        >
          {({ getRootProps, getInputProps }) => (
            // @ts-ignore
            <Box
              data-testid="Drop files"
              borderWidth="1px"
              borderStyle="dashed"
              borderColor={isDragged ? 'navyblue-100' : 'navyblue-300'}
              textAlign="center"
              p={6}
              minWidth={600}
              {...getRootProps()}
            >
              <Text>Drag & Drop your .zip file here</Text>
              <Box p={6}>
                <Img
                  src={folderIllustration}
                  alt="File uploads"
                  nativeWidth={75}
                  nativeHeight={64}
                />
              </Box>
              <Text fontSize="small">or</Text>
              <input data-testid="input-upload" {...getInputProps()} />
              <Box mt={2}>
                <Button size="medium">Select file</Button>
              </Box>
            </Box>
          )}
        </Dropzone>
      </Flex>
    </>
  );
};

export default Upload;
