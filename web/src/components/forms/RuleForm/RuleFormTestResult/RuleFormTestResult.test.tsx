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
  buildTestDetectionSubRecord,
  render,
} from 'test-utils';
import { ComplianceStatusEnum, SeverityEnum } from 'Generated/schema';
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
        ruleFunction: buildTestDetectionSubRecord({ error: buildError({ message: 'Rule' }) }),
        titleFunction: buildTestDetectionSubRecord({ error: buildError({ message: 'Title' }) }),
        dedupFunction: buildTestDetectionSubRecord({ error: buildError({ message: 'Dedup' }) }),
      }),
    });

    const { getByText } = render(<RuleFormTestResult testResult={testResult} />);
    expect(getByText(testResult.functions.ruleFunction.error.message)).toBeInTheDocument();
    expect(getByText(testResult.functions.titleFunction.error.message)).toBeInTheDocument();
    expect(getByText(testResult.functions.dedupFunction.error.message)).toBeInTheDocument();
  });

  it('shows a list of all the non-generic errors for all function outputs', () => {
    const testResult = buildTestRuleRecord({
      error: null,
      functions: buildTestRuleRecordFunctions({
        ruleFunction: buildTestDetectionSubRecord({ error: buildError({ message: 'Rule' }) }),
        titleFunction: buildTestDetectionSubRecord({ error: buildError({ message: 'Title' }) }),
        dedupFunction: buildTestDetectionSubRecord({
          error: buildError({ message: 'Dedup Error' }),
        }),
        referenceFunction: buildTestDetectionSubRecord({
          error: buildError({ message: 'Ref Error' }),
        }),
        runbookFunction: buildTestDetectionSubRecord({
          error: buildError({ message: 'Runbook Error' }),
        }),
        destinationsFunction: buildTestDetectionSubRecord({
          error: buildError({ message: 'Dest Error' }),
        }),
        descriptionFunction: buildTestDetectionSubRecord({
          error: buildError({ message: 'Desc Error' }),
        }),
        severityFunction: buildTestDetectionSubRecord({
          error: buildError({ message: 'Severity Error' }),
        }),
      }),
    });

    const { getByText } = render(<RuleFormTestResult testResult={testResult} />);
    expect(getByText(testResult.functions.ruleFunction.error.message)).toBeInTheDocument();
    expect(getByText(testResult.functions.titleFunction.error.message)).toBeInTheDocument();
    expect(getByText(testResult.functions.dedupFunction.error.message)).toBeInTheDocument();
    expect(getByText(testResult.functions.referenceFunction.error.message)).toBeInTheDocument();
    expect(getByText(testResult.functions.runbookFunction.error.message)).toBeInTheDocument();
    expect(getByText(testResult.functions.destinationsFunction.error.message)).toBeInTheDocument();
    expect(getByText(testResult.functions.descriptionFunction.error.message)).toBeInTheDocument();
    expect(getByText(testResult.functions.severityFunction.error.message)).toBeInTheDocument();
  });

  it("shows functional outputs when errors don't exist", () => {
    const testResult = buildTestRuleRecord({
      error: null,
      functions: buildTestRuleRecordFunctions({
        titleFunction: buildTestDetectionSubRecord({ output: 'Title', error: null }),
        dedupFunction: buildTestDetectionSubRecord({ output: 'Dedup', error: null }),
        referenceFunction: buildTestDetectionSubRecord({ output: 'Reference output', error: null }),
        runbookFunction: buildTestDetectionSubRecord({ output: 'This is a runbook', error: null }),
        descriptionFunction: buildTestDetectionSubRecord({
          output: 'This is a really big description with lots of metadata',
          error: null,
        }),
        // Severity can be one of SeverityEnum but we capitalize the output
        severityFunction: buildTestDetectionSubRecord({
          output: SeverityEnum.Low,
          error: null,
        }),
        destinationsFunction: buildTestDetectionSubRecord({
          output: 'Slack Destination',
          error: null,
        }),
      }),
    });

    const { getByText } = render(<RuleFormTestResult testResult={testResult} />);
    expect(getByText(testResult.functions.titleFunction.output)).toBeInTheDocument();
    expect(getByText(testResult.functions.dedupFunction.output)).toBeInTheDocument();
    expect(getByText(testResult.functions.runbookFunction.output)).toBeInTheDocument();
    expect(getByText(testResult.functions.descriptionFunction.output)).toBeInTheDocument();
    expect(getByText('Low')).toBeInTheDocument();
    expect(getByText(testResult.functions.referenceFunction.output)).toBeInTheDocument();
    expect(getByText(testResult.functions.destinationsFunction.output)).toBeInTheDocument();
  });

  it('matches the snapshot', () => {
    const testResult = buildTestRuleRecord();

    const { container } = render(<RuleFormTestResult testResult={testResult} />);
    expect(container).toMatchSnapshot();
  });
});
