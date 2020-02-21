package custommessage

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

import (
	"context"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambdacontext"

	"github.com/panther-labs/panther/pkg/lambdalogger"
	"github.com/panther-labs/panther/pkg/oplog"
)

// HandleEvent routes Custom Message event based on the triggerSource
func HandleEvent(ctx context.Context, event *events.CognitoEventUserPoolsCustomMessage) (
	returnedEvent *events.CognitoEventUserPoolsCustomMessage, err error) {

	lc, _ := lambdalogger.ConfigureGlobal(ctx, nil)
	operation := oplog.NewManager("api", "custom_message").Start(lc.InvokedFunctionArn).WithMemUsed(lambdacontext.MemoryLimitInMB)
	defer func() {
		operation.Stop().Log(err)
	}()

	switch ts := event.TriggerSource; ts {
	case "CustomMessage_ForgotPassword":
		event, err = handleForgotPassword(event)
		return event, err
	default:
		return event, nil
	}
}
