"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.SortDirEnum = exports.SeverityEnum = exports.ListRulesSortFieldsEnum = exports.ListResourcesSortFieldsEnum = exports.ListPoliciesSortFieldsEnum = exports.ListAlertsSortFieldsEnum = exports.DestinationTypeEnum = exports.ComplianceStatusEnum = exports.AnalysisTypeEnum = exports.AlertTypesEnum = exports.AlertStatusesEnum = exports.AccountTypeEnum = void 0;
var AccountTypeEnum;
(function (AccountTypeEnum) {
    AccountTypeEnum["Aws"] = "aws";
})(AccountTypeEnum = exports.AccountTypeEnum || (exports.AccountTypeEnum = {}));
var AlertStatusesEnum;
(function (AlertStatusesEnum) {
    AlertStatusesEnum["Open"] = "OPEN";
    AlertStatusesEnum["Triaged"] = "TRIAGED";
    AlertStatusesEnum["Closed"] = "CLOSED";
    AlertStatusesEnum["Resolved"] = "RESOLVED";
})(AlertStatusesEnum = exports.AlertStatusesEnum || (exports.AlertStatusesEnum = {}));
var AlertTypesEnum;
(function (AlertTypesEnum) {
    AlertTypesEnum["Rule"] = "RULE";
    AlertTypesEnum["RuleError"] = "RULE_ERROR";
})(AlertTypesEnum = exports.AlertTypesEnum || (exports.AlertTypesEnum = {}));
var AnalysisTypeEnum;
(function (AnalysisTypeEnum) {
    AnalysisTypeEnum["Rule"] = "RULE";
    AnalysisTypeEnum["Policy"] = "POLICY";
})(AnalysisTypeEnum = exports.AnalysisTypeEnum || (exports.AnalysisTypeEnum = {}));
var ComplianceStatusEnum;
(function (ComplianceStatusEnum) {
    ComplianceStatusEnum["Error"] = "ERROR";
    ComplianceStatusEnum["Fail"] = "FAIL";
    ComplianceStatusEnum["Pass"] = "PASS";
})(ComplianceStatusEnum = exports.ComplianceStatusEnum || (exports.ComplianceStatusEnum = {}));
var DestinationTypeEnum;
(function (DestinationTypeEnum) {
    DestinationTypeEnum["Slack"] = "slack";
    DestinationTypeEnum["Pagerduty"] = "pagerduty";
    DestinationTypeEnum["Github"] = "github";
    DestinationTypeEnum["Jira"] = "jira";
    DestinationTypeEnum["Opsgenie"] = "opsgenie";
    DestinationTypeEnum["Msteams"] = "msteams";
    DestinationTypeEnum["Sns"] = "sns";
    DestinationTypeEnum["Sqs"] = "sqs";
    DestinationTypeEnum["Asana"] = "asana";
    DestinationTypeEnum["Customwebhook"] = "customwebhook";
})(DestinationTypeEnum = exports.DestinationTypeEnum || (exports.DestinationTypeEnum = {}));
var ListAlertsSortFieldsEnum;
(function (ListAlertsSortFieldsEnum) {
    ListAlertsSortFieldsEnum["CreatedAt"] = "createdAt";
})(ListAlertsSortFieldsEnum = exports.ListAlertsSortFieldsEnum || (exports.ListAlertsSortFieldsEnum = {}));
var ListPoliciesSortFieldsEnum;
(function (ListPoliciesSortFieldsEnum) {
    ListPoliciesSortFieldsEnum["ComplianceStatus"] = "complianceStatus";
    ListPoliciesSortFieldsEnum["Enabled"] = "enabled";
    ListPoliciesSortFieldsEnum["Id"] = "id";
    ListPoliciesSortFieldsEnum["LastModified"] = "lastModified";
    ListPoliciesSortFieldsEnum["Severity"] = "severity";
    ListPoliciesSortFieldsEnum["ResourceTypes"] = "resourceTypes";
})(ListPoliciesSortFieldsEnum = exports.ListPoliciesSortFieldsEnum || (exports.ListPoliciesSortFieldsEnum = {}));
var ListResourcesSortFieldsEnum;
(function (ListResourcesSortFieldsEnum) {
    ListResourcesSortFieldsEnum["ComplianceStatus"] = "complianceStatus";
    ListResourcesSortFieldsEnum["Id"] = "id";
    ListResourcesSortFieldsEnum["LastModified"] = "lastModified";
    ListResourcesSortFieldsEnum["Type"] = "type";
})(ListResourcesSortFieldsEnum = exports.ListResourcesSortFieldsEnum || (exports.ListResourcesSortFieldsEnum = {}));
var ListRulesSortFieldsEnum;
(function (ListRulesSortFieldsEnum) {
    ListRulesSortFieldsEnum["Enabled"] = "enabled";
    ListRulesSortFieldsEnum["Id"] = "id";
    ListRulesSortFieldsEnum["LastModified"] = "lastModified";
    ListRulesSortFieldsEnum["LogTypes"] = "logTypes";
    ListRulesSortFieldsEnum["Severity"] = "severity";
})(ListRulesSortFieldsEnum = exports.ListRulesSortFieldsEnum || (exports.ListRulesSortFieldsEnum = {}));
var SeverityEnum;
(function (SeverityEnum) {
    SeverityEnum["Info"] = "INFO";
    SeverityEnum["Low"] = "LOW";
    SeverityEnum["Medium"] = "MEDIUM";
    SeverityEnum["High"] = "HIGH";
    SeverityEnum["Critical"] = "CRITICAL";
})(SeverityEnum = exports.SeverityEnum || (exports.SeverityEnum = {}));
var SortDirEnum;
(function (SortDirEnum) {
    SortDirEnum["Ascending"] = "ascending";
    SortDirEnum["Descending"] = "descending";
})(SortDirEnum = exports.SortDirEnum || (exports.SortDirEnum = {}));
