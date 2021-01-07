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

/* eslint-disable no-param-reassign */
import ace from 'brace';
import { theme } from 'pouncejs';

// @ts-ignore
ace.define(
  'ace/theme/panther',
  ['require', 'exports', 'module', 'ace/lib/dom'],
  (acequire: any, exports: any) => {
    exports.isDark = true;
    exports.cssClass = 'ace-panther';
    exports.cssText = `
   
  .ace_editor * {
    font-family: inherit !important;
  } 
    
  .ace-panther .ace_gutter {
    background: #011e3a;
    color: white
  }
  
  .ace-panther.ace_editor.ace_autocomplete {
    background: ${theme.colors['navyblue-400']};
    color: white;
    border: none;
  }
  
  .ace-panther.ace_editor.ace_autocomplete .ace_completion-highlight {
    color: ${theme.colors['blue-300']};
  }
  
  .ace-panther.ace_editor.ace_autocomplete .ace_marker-layer .ace_active-line {
    background-color: ${theme.colors['navyblue-300']};
  }
  
  .ace-panther.ace_editor.ace_autocomplete .ace_marker-layer .ace_line-hover {
    background-color: ${theme.colors['navyblue-300']};
  }
  
  .ace-panther .ace_print-margin {
    width: 1px;
    background: #555555
  }
  
  .ace-panther {
    background-color: #002240;
    color: #FFFFFF
  }
  
  .ace-panther .ace_cursor {
    color: #FFFFFF
  }
  
  .ace-panther .ace_marker-layer .ace_selection {
    background: rgba(179, 101, 57, 0.75)
  }
  
  .ace-panther.ace_multiselect .ace_selection.ace_start {
    box-shadow: 0 0 3px 0px #002240;
  }
  
  .ace-panther .ace_marker-layer .ace_step {
    background: rgb(127, 111, 19)
  }
  
  .ace-panther .ace_marker-layer .ace_bracket {
    margin: -1px 0 0 -1px;
    border: 1px solid rgba(255, 255, 255, 0.15)
  }
  .ace-panther .ace_marker-layer .ace_active-line {
    background: rgba(0, 0, 0, 0.35)
  }
  .ace-panther .ace_gutter-active-line {
    background-color: rgba(0, 0, 0, 0.35)
  }
  
  .ace-panther .ace_marker-layer .ace_selected-word {
    border: 1px solid rgba(179, 101, 57, 0.75)
  }
  
  .ace-panther .ace_invisible {
    color: rgba(255, 255, 255, 0.15)
  }
  
  .ace-panther .ace_keyword,
  .ace-panther .ace_meta {
    color: ${theme.colors['yellow-500']}
  }
  
  .ace-panther .ace_constant,
  .ace-panther .ace_constant.ace_character,
  .ace-panther .ace_constant.ace_character.ace_escape,
  .ace-panther .ace_constant.ace_other {
    color: ${theme.colors['red-300']}
  }
  
  .ace-panther .ace_invalid {
    color: #F8F8F8;
    background-color: #800F00
  }
  
  .ace-panther .ace_support {
    color: white
  }
  
  .ace-panther .ace_support.ace_constant {
    color: #EB939A
  }
  .ace-panther .ace_fold {
    background-color: ${theme.colors['yellow-500']};
    border-color: #FFFFFF
  }
  .ace-panther .ace_support.ace_function {
    color: ${theme.colors['yellow-500']}
  }
  
  .ace-panther .ace_storage {
    color: ${theme.colors['yellow-500']}
  }
  
  .ace-panther .ace_entity {
    color: ${theme.colors['yellow-500']}
  }
  
  .ace-panther .ace_string {
    color: ${theme.colors['teal-500']};
  }
  
  .ace-panther .ace_string.ace_regexp {
    color: #80FFC2
  }
  
  .ace-panther .ace_comment {
    font-style: italic;
    color: ${theme.colors['blue-400']}
  }
  
  .ace-panther .ace_comment.ace_placeholder {
    margin-top: 10px;
  }
  
  .ace-panther .ace_heading,
  .ace-panther .ace_markup.ace_heading {
    color: #C8E4FD;
    background-color: #001221
  }
  
  .ace-panther .ace_variable {
    color: ${theme.colors['gray-50']}
  }
  
  .ace-panther .ace_variable.ace_language {
    color: #FF80E1
  }
  
  .ace-panther .ace_meta.ace_tag {
    color: ${theme.colors['blue-300']}
  }
  
  .ace-panther .ace_rightAlignedText {
    color: ${theme.colors['gray-300']}
  }
  
  .ace-panther .ace_indent-guide {
    background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAACCAYAAACZgbYnAAAAEklEQVQImWNgYGBgYHCLSvkPAAP3AgSDTRd4AAAAAElFTkSuQmCC) right repeat-y
  }
`;

    const dom = acequire('../lib/dom');
    dom.importCssString(exports.cssText, exports.cssClass);
  }
);
