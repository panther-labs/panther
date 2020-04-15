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
import { IAceEditorProps } from 'react-ace';

// Lazy-load the ace editor. Make sure that both editor and modes get bundled under the same chunk
const AceEditor = React.lazy(() => import(/* webpackChunkName: "ace-editor" */ 'react-ace'));

export type Completion = { value: string; type: string };
export type EditorProps = IAceEditorProps & {
  fallback?: React.ReactElement;
  completions?: Completion[];
};

const Editor: React.FC<EditorProps> = ({ fallback = null, completions = [], ...rest }) => {
  const theme = useTheme();

  // Asynchronously load (post-mount) all the mode & themes
  React.useEffect(() => {
    import(/* webpackChunkName: "ace-editor" */ 'brace/mode/json');
    import(/* webpackChunkName: "ace-editor" */ 'brace/mode/sql');
    import(/* webpackChunkName: "ace-editor" */ 'brace/mode/python');
    import(/* webpackChunkName: "ace-editor" */ 'brace/ext/language_tools');
    import(/* webpackChunkName: "ace-editor" */ './theme');
  }, []);

  React.useEffect(() => {
    if (completions.length) {
      import(/* webpackChunkName: "ace-editor" */ 'brace').then(({ acequire }) => {
        // @ts-ignore
        // Project is so old that I cba to deal with typings
        acequire(['ace/ext/language_tools'], langTools => {
          langTools.addCompleter({
            getCompletions: (e, session, pos, prefix, callback) => {
              callback(
                null,
                completions.map(({ value, type }) => ({ name: value, value, score: 0, meta: type }))
              );
            },
          });
        });
      });
    }
  }, [completions]);

  const baseAceEditorConfig = React.useMemo(
    () => ({
      enableBasicAutocompletion: true,
      enableLiveAutocompletion: true,
      highlightActiveLine: false,
      fontSize: theme.fontSizes[2],
      editorProps: {
        $blockScrolling: Infinity,
      },
      wrapEnabled: true,
      theme: 'panther',
      maxLines: Infinity,
      style: {
        zIndex: 0,
      },
    }),
    [theme]
  );

  return (
    <React.Suspense fallback={fallback}>
      <AceEditor {...baseAceEditorConfig} {...rest} />
    </React.Suspense>
  );
};

export default React.memo(Editor);
