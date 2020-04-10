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
import { IAceEditorProps } from 'react-ace/lib/ace';

// Lazy-load the ace editor. Make sure that both editor and modes get bundled under the same chunk
const AceEditor = React.lazy(() => import(/* webpackChunkName: "ace-editor" */ 'react-ace'));

const baseAceEditorConfig = {
  fontSize: '16px',
  editorProps: {
    $blockScrolling: Infinity,
  },
  wrapEnabled: true,
  theme: 'cobalt',
  showPrintMargin: true,
  showGutter: true,
  highlightActiveLine: true,
  maxLines: Infinity,
  style: {
    zIndex: 0,
  },
};

export type EditorProps = IAceEditorProps;

const Editor: React.FC<EditorProps> = props => {
  // Asynchronously load (post-mount) all the mode & themes
  React.useEffect(() => {
    import(/* webpackChunkName: "ace-editor" */ 'brace/mode/json');
    import(/* webpackChunkName: "ace-editor" */ 'brace/mode/python');
    import(/* webpackChunkName: "ace-editor" */ 'brace/theme/cobalt');
  }, []);

  return (
    <React.Suspense fallback={null}>
      <AceEditor {...baseAceEditorConfig} {...props} />
    </React.Suspense>
  );
};

export default React.memo(Editor);
