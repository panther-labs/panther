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
import { useTheme } from 'pouncejs';
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

  const jsonViewerStyle = React.useMemo(
    () => ({
      fontFamily: 'inherit',
      fontSize: remToPx(theme.fontSizes.medium),
      background: 'transparent',
      wordBreak: 'break-all' as const,
    }),
    [theme]
  );

  const handleCopy = React.useCallback(copy => {
    copyTextToClipboard(JSON.stringify(copy.src, null, '\t'));
  }, []);

  return (
    <React.Suspense fallback={null}>
      <ReactJSONView
        src={data}
        name={false}
        theme="shapeshifter"
        iconStyle="triangle"
        displayObjectSize={false}
        displayDataTypes={false}
        collapsed={collapsed || 1}
        style={jsonViewerStyle}
        sortKeys
        enableClipboard={handleCopy}
      />
    </React.Suspense>
  );
};

export default JsonViewer;
