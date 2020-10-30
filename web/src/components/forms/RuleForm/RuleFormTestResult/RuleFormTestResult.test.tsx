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
import {
  buildError,
  buildTestRuleRecord,
  buildTestRuleRecordFunctions,
  buildTestRuleSubRecord,
  render,
} from 'test-utils';
import { ComplianceStatusEnum } from 'Generated/schema';
import RuleFormTestResult from './RuleFormTestResult';

describe('RuleFormTestResult', () => {
  it('shows the name & status of the test', () => {
    const testResult = buildTestRuleRecord({ passed: true });

    const { getByText } = render(<RuleFormTestResult testResult={testResult} />);
    expect(getByText(testResult.name)).toBeInTheDocument();
    expect(getByText(ComplianceStatusEnum.Pass)).toBeInTheDocument();
  });

  it('shows a generic error when it exists', () => {
    const testResult = buildTestRuleRecord({
      functions: {
        ruleFunction: null,
        titleFunction: null,
        dedupFunction: null,
      },
    });

    const { getByText } = render(<RuleFormTestResult testResult={testResult} />);
    expect(getByText(testResult.error.message)).toBeInTheDocument();
  });

  it('shows a list of all the non-generic errors', () => {
    const testResult = buildTestRuleRecord({
      error: null,
      functions: buildTestRuleRecordFunctions({
        ruleFunction: buildTestRuleSubRecord({ error: buildError({ message: 'Rule' }) }),
        titleFunction: buildTestRuleSubRecord({ error: buildError({ message: 'Title' }) }),
        dedupFunction: buildTestRuleSubRecord({ error: buildError({ message: 'Dedup' }) }),
      }),
    });

    const { getByText } = render(<RuleFormTestResult testResult={testResult} />);
    expect(getByText(testResult.functions.ruleFunction.error.message)).toBeInTheDocument();
    expect(getByText(testResult.functions.titleFunction.error.message)).toBeInTheDocument();
    expect(getByText(testResult.functions.dedupFunction.error.message)).toBeInTheDocument();
  });

  it("shows title & dedup outputs when errors don't exist", () => {
    const testResult = buildTestRuleRecord({
      error: null,
      functions: buildTestRuleRecordFunctions({
        titleFunction: buildTestRuleSubRecord({ output: 'Title', error: null }),
        dedupFunction: buildTestRuleSubRecord({ output: 'Dedup', error: null }),
      }),
    });

    const { getByText } = render(<RuleFormTestResult testResult={testResult} />);
    expect(getByText(testResult.functions.titleFunction.output)).toBeInTheDocument();
    expect(getByText(testResult.functions.dedupFunction.output)).toBeInTheDocument();
  });

  it('matches the snapshot', () => {
    const testResult = buildTestRuleRecord();

    const { container } = render(<RuleFormTestResult testResult={testResult} />);
    expect(container).toMatchSnapshot();
  });
});
