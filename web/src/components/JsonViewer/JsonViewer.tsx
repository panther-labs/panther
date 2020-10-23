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
import { useTheme, Box, Button } from 'pouncejs';
import { copyTextToClipboard, remToPx } from 'Helpers/utils';

const ReactJSONView = React.lazy(() =>
  import(/* webpackChunkName: 'react-json-view' */ 'react-json-view')
);

interface JsonViewerProps {
  data: Record<string, unknown>;
  collapsed?: boolean;
}

const JsonViewer: React.FC<JsonViewerProps> = ({ data, collapsed }) => {
  const theme = useTheme();
  const [isExpanded, toggle] = React.useState(false);

  const toggleDepth = React.useCallback(() => {
    toggle(!isExpanded);
  }, [isExpanded]);

  const jsonViewerStyle = React.useMemo(
    () => ({
      fontFamily: 'inherit',
      fontSize: remToPx(theme.fontSizes.medium),
      background: 'transparent',
      wordBreak: 'break-all' as const,
    }),
    [theme]
  );

  const depth = React.useMemo(() => {
    if (collapsed && !isExpanded) {
      return false;
    }
    if (isExpanded) {
      return 100;
    }
    return 1;
  }, [collapsed, isExpanded]);

  const handleCopy = React.useCallback(copy => {
    copyTextToClipboard(JSON.stringify(copy.src, null, '\t'));
  }, []);

  return (
    <React.Suspense fallback={null}>
      <Box position="relative" width="100%">
        <Box position="absolute" top="0" right="0" zIndex={10}>
          <Button
            data-testid="toggle-json"
            size="medium"
            variantColor="navyblue"
            onClick={toggleDepth}
          >
            {isExpanded ? 'Collapse All' : 'Expand All'}
          </Button>
        </Box>
        <ReactJSONView
          data-testId="json-viewer"
          src={data}
          name={false}
          theme="shapeshifter"
          iconStyle="triangle"
          displayObjectSize={false}
          displayDataTypes={false}
          collapsed={depth}
          style={jsonViewerStyle}
          sortKeys
          enableClipboard={handleCopy}
        />
      </Box>
    </React.Suspense>
  );
};

export default JsonViewer;
