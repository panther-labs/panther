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
import { logError } from 'Helpers/loggers';
import { Card, Text, Flex } from 'pouncejs';

interface ErrorBoundaryProps {
  fallbackStrategy?: 'passthrough' | 'invisible' | 'placeholder';
}

interface ErrorBoundaryState {
  hasError: boolean;
}

class ErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
  static defaultProps: Partial<ErrorBoundaryProps>;

  state = { hasError: false };

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    // Display fallback UI
    this.setState({ hasError: true });

    // send this error to our logging service.
    logError(error, { extras: info });
  }

  render() {
    const { fallbackStrategy, children } = this.props;

    // if no error occurs -> render as normal
    if (!this.state.hasError) {
      return children;
    }

    // else decide what to show based on the selected strategy
    switch (fallbackStrategy) {
      case 'invisible':
        return null;
      case 'placeholder':
        return (
          <Card bg="red100" width="100%" height="100%">
            <Flex align="center" justify="center" width="100%" height="100%">
              <Text size="large" color="red300" py={5} px={4}>
                Something went wrong and we could not correctly display this content
              </Text>
            </Flex>
          </Card>
        );
      case 'passthrough':
      default:
        return children;
    }
  }
}

ErrorBoundary.defaultProps = {
  fallbackStrategy: 'placeholder',
};

export default ErrorBoundary;
