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
import { FastField } from 'formik';
import { Link, IconButton, FormHelperText, Card, Box, Flex, Heading } from 'pouncejs';
import FormikEditor from 'Components/fields/Editor';
import { Link as RRLink } from 'react-router-dom';
import urls from 'Source/urls';

interface BaseDetectionFormEditorSectionProps {
  type: 'rule' | 'policy';
}

const BaseDetectionFormEditorSection: React.FC<BaseDetectionFormEditorSectionProps> = ({
  type,
}) => {
  const [open, setOpen] = React.useState(true);
  const isPolicy = type === 'policy';

  return (
    <Box>
      <Card variant="dark" p={4}>
        <Flex align="center" spacing={4}>
          <IconButton
            variant="ghost"
            variantBorderStyle="circle"
            active={open}
            variantColor="darkblue"
            icon={open ? 'caret-up' : 'caret-down'}
            onClick={() => setOpen(!open)}
            size="medium"
            aria-label="Toggle Editor visibility"
          />
          <Heading size="x-small">{isPolicy ? 'Policy Function' : 'Rule Function'} </Heading>
        </Flex>
        {open && (
          <Box mt={5}>
            <FastField
              as={FormikEditor}
              placeholder={`# Enter the body of the ${type} here...`}
              name="body"
              width="100%"
              minLines={10}
              mode="python"
              required
              aria-describedby="editor-helper-text"
            />
          </Box>
        )}
      </Card>
      <FormHelperText id="editor-helper-text" mt={3}>
        Need to define re-usable functions? Define them in a
        <Link ml={1} as={RRLink} to={urls.settings.globalPythonModules.list()}>
          global module
        </Link>
      </FormHelperText>
    </Box>
  );
};

export default React.memo(BaseDetectionFormEditorSection);
