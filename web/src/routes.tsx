/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
import ListPoliciesPage from 'Pages/list-policies';
import OverviewPage from 'Pages/ComplianceOverview';
import ListResourcesPage from 'Pages/list-resources';
import ResourceDetailsPage from 'Pages/resource-details';
import PolicyDetailsPage from 'Pages/policy-details';
import GeneralSettingsPage from 'Pages/general-settings';
import SignInPage from 'Pages/sign-in';
import DestinationsPage from 'Pages/destinations';
import UsersPage from 'Pages/users';
import RuleDetailsPage from 'Pages/rule-details';
import ListRulesPage from 'Pages/list-rules';
import EditRulePage from 'Pages/edit-rule';
import CreateRulePage from 'Pages/create-rule';
import AlertDetailsPage from 'Pages/AlertDetails';
import EditPolicyPage from 'Pages/edit-policy';
import CreatePolicyPage from 'Pages/create-policy';
import ListAlertsPage from 'Pages/list-alerts';
import Layout from 'Components/Layout';
import CreateComplianceSourcePage from 'Pages/create-compliance-source';
import CreateLogSourcePage from 'Pages/create-log-source';
import ListComplianceSourcesPagee from 'Pages/list-compliance-sources';
import ListLogSourcesPage from 'Pages/list-log-sources';
import urls from 'Source/urls';
import GuardedRoute from 'Components/GuardedRoute';
import ForgotPasswordPage from 'Pages/forgot-password';
import ForgotPasswordConfirmPage from 'Pages/forgot-password-confirm';
import ErrorBoundary from 'Components/ErrorBoundary';
import Page404 from 'Pages/404';
import APIErrorFallback from 'Components/utils/api-error-fallback';
import LogAnalysisOverview from 'Pages/log-analysis-overview';
import PromptController from 'Components/utils/prompt-controller';

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
                /******************** COMPLIANCE ******************************/
                <Redirect exact from="/" to={urls.compliance.overview()} />
                <Redirect exact from={urls.compliance.home()} to={urls.compliance.overview()} />
                <Route exact path={urls.compliance.overview()} component={OverviewPage} />
                <Route exact path={urls.compliance.policies.list()} component={ListPoliciesPage} />
                <Route
                  exact
                  path={urls.compliance.policies.create()}
                  component={CreatePolicyPage}
                />
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
                  component={ListComplianceSourcesPagee}
                />
                <Route
                  exact
                  path={urls.compliance.sources.create()}
                  component={CreateComplianceSourcePage}
                />
                /******************** LOG ANALYSIS ******************************/
                <Redirect exact from={urls.logAnalysis.home()} to={urls.logAnalysis.overview()} />
                <Route exact path={urls.logAnalysis.overview()} component={LogAnalysisOverview} />
                <Route exact path={urls.logAnalysis.rules.list()} component={ListRulesPage} />
                <Route exact path={urls.logAnalysis.rules.create()} component={CreateRulePage} />
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
                  path={urls.logAnalysis.sources.create()}
                  component={CreateLogSourcePage}
                />
                /******************** SETTINGS ******************************/
                <Route exact path={urls.settings.general()} component={GeneralSettingsPage} />
                <Route exact path={urls.settings.users()} component={UsersPage} />
                <Route exact path={urls.settings.destinations()} component={DestinationsPage} />
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
