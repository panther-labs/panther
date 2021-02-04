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
import { Redirect, Route, Switch } from 'react-router-dom';
import OverviewPage from 'Pages/ComplianceOverview';
import ListResourcesPage from 'Pages/ListResources';
import ResourceDetailsPage from 'Pages/ResourceDetails';
import PolicyDetailsPage from 'Pages/PolicyDetails';
import GeneralSettingsPage from 'Pages/GeneralSettings';
import SignInPage from 'Pages/SignIn';
import ListDestinationsPage from 'Pages/ListDestinations';
import CreateDestinationPage from 'Pages/CreateDestination';
import EditDestinationPage from 'Pages/EditDestination';
import UsersPage from 'Pages/Users';
import RuleDetailsPage from 'Pages/RuleDetails';
import LandingPage from 'Pages/Landing';
import EditRulePage from 'Pages/EditRule';
import CreateDetectionPage from 'Pages/CreateDetection';
import AlertDetailsPage from 'Pages/AlertDetails';
import EditPolicyPage from 'Pages/EditPolicy';
import ListAlertsPage from 'Pages/ListAlerts';
import Layout from 'Components/Layout';
import CreateComplianceSourcePage from 'Pages/CreateComplianceSource';
import CreateLogSourcePage from 'Pages/CreateLogSource';
import ListComplianceSourcesPage from 'Pages/ListComplianceSources';
import ListLogSourcesPage from 'Pages/ListLogSources';
import urls from 'Source/urls';
import GuardedRoute from 'Components/GuardedRoute';
import ForgotPasswordPage from 'Pages/ForgotPassword';
import ForgotPasswordConfirmPage from 'Pages/ForgotPasswordConfirm';
import ErrorBoundary from 'Components/ErrorBoundary';
import SupportPage from 'Pages/Support';
import Page404 from 'Pages/404';
import APIErrorFallback from 'Components/utils/ApiErrorFallback';
import LogAnalysisOverview from 'Pages/LogAnalysisOverview';
import EditComplianceSourcePage from 'Pages/EditComplianceSource';
import EditS3LogSourcePage from 'Pages/EditS3LogSource';
import PromptController from 'Components/utils/PromptController';
import LogSourceOnboarding from 'Pages/LogSourceOnboarding';
import BulkUploaderPage from 'Pages/BulkUploader';
import ListGlobalPythonModulesPage from 'Pages/ListGlobalPythonModules';
import CreateGlobalPythonModulePage from 'Pages/CreateGlobalPythonModule';
import EditGlobalPythonModulePage from 'Pages/EditGlobalPythonModule';
import EditSqsLogSource from 'Pages/EditSqsLogSource';
import CreateCustomLogPage from 'Pages/CreateCustomLog';
import ListCustomLogsPage from 'Pages/ListCustomLogs';
import CustomLogDetailsPage from 'Pages/CustomLogDetails';
import CreateDataModelPage from 'Pages/CreateDataModel';
import EditDataModelPage from 'Pages/EditDataModel';
import ListDataModelsPage from 'Pages/ListDataModels';
import EditCustomLogPage from 'Pages/EditCustomLog';
import ListDetectionsPage from 'Pages/ListDetections';

// Main page container for the web application, Navigation bar and Content body goes here
const PrimaryPageLayout: React.FunctionComponent = () => {
  return (
    <Switch>
      <GuardedRoute
        limitAccessTo="anonymous"
        exact
        path={urls.account.auth.signIn()}
        component={SignInPage}
      />
      <GuardedRoute
        limitAccessTo="anonymous"
        exact
        path={urls.account.auth.forgotPassword()}
        component={ForgotPasswordPage}
      />
      <GuardedRoute
        limitAccessTo="anonymous"
        exact
        path={urls.account.auth.resetPassword()}
        component={ForgotPasswordConfirmPage}
      />
      <GuardedRoute path="/" limitAccessTo="authenticated">
        <Layout>
          <ErrorBoundary>
            <APIErrorFallback>
              <Switch>
                <Route exact path="/" component={LandingPage} />
                <Route exact path={urls.detections.list()} component={ListDetectionsPage} />
                {/* ******************* COMPLIANCE ***************************** */}
                <Redirect exact from={urls.compliance.home()} to={urls.compliance.overview()} />
                <Redirect
                  exact
                  from={urls.compliance.policies.list()}
                  to={`${urls.detections.list()}?analysisTypes[]=POLICY&page=1&sortBy=lastModified&sortDir=descending`}
                />
                <Route exact path={urls.compliance.overview()} component={OverviewPage} />
                <Route exact path={urls.detections.create()} component={CreateDetectionPage} />
                <Route
                  exact
                  path={urls.compliance.policies.details(':id')}
                  component={PolicyDetailsPage}
                />
                <Route
                  exact
                  path={urls.compliance.policies.edit(':id')}
                  component={EditPolicyPage}
                />
                <Route
                  exact
                  path={urls.compliance.resources.list()}
                  component={ListResourcesPage}
                />
                <Route
                  exact
                  path={urls.compliance.resources.details(':id')}
                  component={ResourceDetailsPage}
                />
                <Route
                  exact
                  path={urls.compliance.sources.list()}
                  component={ListComplianceSourcesPage}
                />
                <Route
                  exact
                  path={urls.compliance.sources.create()}
                  component={CreateComplianceSourcePage}
                />
                <Route
                  exact
                  path={urls.compliance.sources.edit(':id')}
                  component={EditComplianceSourcePage}
                />
                {/* ******************* LOG ANALYSIS ***************************** */}
                <Redirect exact from={urls.logAnalysis.home()} to={urls.logAnalysis.overview()} />
                <Redirect
                  exact
                  from={urls.logAnalysis.rules.list()}
                  to={`${urls.detections.list()}?analysisTypes[]=RULE&page=1&sortBy=lastModified&sortDir=descending`}
                />
                <Route exact path={urls.logAnalysis.overview()} component={LogAnalysisOverview} />
                <Route
                  exact
                  path={urls.logAnalysis.rules.details(':id')}
                  component={RuleDetailsPage}
                />
                <Route exact path={urls.logAnalysis.rules.edit(':id')} component={EditRulePage} />
                <Route exact path={urls.logAnalysis.alerts.list()} component={ListAlertsPage} />
                <Route
                  exact
                  path={urls.logAnalysis.alerts.details(':id')}
                  component={AlertDetailsPage}
                />
                <Route
                  exact
                  path={urls.logAnalysis.sources.list()}
                  component={ListLogSourcesPage}
                />
                <Route
                  exact
                  path={urls.logAnalysis.sources.create(':type')}
                  component={CreateLogSourcePage}
                />
                <Route
                  exact
                  path={urls.logAnalysis.sources.create()}
                  component={LogSourceOnboarding}
                />
                <Route
                  exact
                  path={urls.logAnalysis.sources.edit(':id', 's3')}
                  component={EditS3LogSourcePage}
                />
                <Route
                  exact
                  path={urls.logAnalysis.sources.edit(':id', 'sqs')}
                  component={EditSqsLogSource}
                />
                <Route
                  exact
                  path={urls.logAnalysis.dataModels.list()}
                  component={ListDataModelsPage}
                />
                <Route
                  exact
                  path={urls.logAnalysis.dataModels.create()}
                  component={CreateDataModelPage}
                />
                <Route
                  exact
                  path={urls.logAnalysis.dataModels.edit(':id')}
                  component={EditDataModelPage}
                />
                <Redirect
                  exact
                  from={urls.logAnalysis.dataModels.details(':id')}
                  to={urls.logAnalysis.dataModels.edit(':id')}
                />
                <Redirect
                  exact
                  from={`${urls.logAnalysis.sources.list()}:type`}
                  to={urls.logAnalysis.sources.list()}
                />
                {/* ******************* SETTINGS ***************************** */}
                <Redirect exact from={urls.settings.home()} to={urls.settings.general()} />
                <Route exact path={urls.settings.general()} component={GeneralSettingsPage} />
                <Route exact path={urls.settings.general()} component={GeneralSettingsPage} />
                <Route
                  exact
                  path={urls.settings.globalPythonModules.list()}
                  component={ListGlobalPythonModulesPage}
                />
                <Route
                  exact
                  path={urls.settings.globalPythonModules.create()}
                  component={CreateGlobalPythonModulePage}
                />
                <Route
                  exact
                  path={urls.settings.globalPythonModules.edit(':id')}
                  component={EditGlobalPythonModulePage}
                />
                <Route exact path={urls.settings.bulkUploader()} component={BulkUploaderPage} />
                <Redirect
                  exact
                  from={`${urls.settings.globalPythonModules.list()}:id`}
                  to={urls.settings.globalPythonModules.edit(':id')}
                />
                <Route exact path={urls.settings.users()} component={UsersPage} />
                <Route
                  exact
                  path={urls.settings.destinations.create()}
                  component={CreateDestinationPage}
                />
                <Route
                  exact
                  path={urls.settings.destinations.edit(':id')}
                  component={EditDestinationPage}
                />
                <Route
                  exact
                  path={urls.settings.destinations.list()}
                  component={ListDestinationsPage}
                />
                <Route
                  exact
                  path={urls.logAnalysis.customLogs.create()}
                  component={CreateCustomLogPage}
                />
                <Route
                  exact
                  path={urls.logAnalysis.customLogs.details(':logType')}
                  component={CustomLogDetailsPage}
                />
                <Route
                  exact
                  path={urls.logAnalysis.customLogs.edit(':logType')}
                  component={EditCustomLogPage}
                />
                <Route
                  exact
                  path={urls.logAnalysis.customLogs.list()}
                  component={ListCustomLogsPage}
                />
                <Route exact path={urls.account.support()} component={SupportPage} />
                <Route component={Page404} />
              </Switch>
            </APIErrorFallback>
          </ErrorBoundary>
        </Layout>
        <PromptController />
      </GuardedRoute>
    </Switch>
  );
};

export default React.memo(PrimaryPageLayout);
