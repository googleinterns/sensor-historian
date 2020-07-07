// Copyright 2020 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sensorserviceutils

import (
	"reflect"
	"strings"
	"testing"

	"github.com/googleinterns/sensor-historian/bugreportutils"
	acpb "github.com/googleinterns/sensor-historian/pb/activeconnection_proto"
)

func TestParse(t *testing.T) {
	meta := &bugreportutils.MetaInfo{
		DeviceID:   `123456789012345678`,
		SdkVersion: 21,
		Sensors: map[int32]bugreportutils.SensorInfo{
			1: {
				Name:        `BMI160 accelerometer`,
				Type:        `android.sensor.accelerometer`,
				Number:      1,
				Version:     1,
				RequestMode: `continuous`,
				WakeUp:      false,
				MaxDelay:    160000,
				MinDelay:    5000,
				Batch:       true,
				Max:         3000,
			},
			7: {
				Name:        `RPR0521 light`,
				Type:        `android.sensor.light`,
				Number:      7,
				Version:     1,
				RequestMode: `on-change`,
				WakeUp:      false,
				MaxDelay:    10000000,
				MinDelay:    200000,
				Batch:       false,
			},
			4: {
				Name:        `BMP280 pressure`,
				Type:        `android.sensor.pressure`,
				Number:      4,
				Version:     1,
				RequestMode: `continuous`,
				WakeUp:      false,
				MaxDelay:    10000000,
				MinDelay:    100000,
				Batch:       true,
				Max:         300,
			},
			31: {
				Name:        `Window Orientation`,
				Type:        `com.google.sensor.window_orientation`,
				Number:      31,
				Version:     1,
				RequestMode: `on-change`,
				WakeUp:      true,
				MaxDelay:    0,
				MinDelay:    0,
				Batch:       false,
			},
			24: {
				Name:        `BMI160 Step counter`,
				Type:        `android.sensor.step_counter`,
				Number:      24,
				Version:     1,
				RequestMode: `on-change`,
				WakeUp:      false,
				MaxDelay:    0,
				MinDelay:    0,
				Batch:       false,
			},
		},
	}
	tests := []struct {
		name, finput   string
		wantActiveConn []*acpb.ActiveConn
	}{
		{
			name: "Parse (all entries)",
			finput: strings.Join([]string{
				`========================================================`,
				`== dumpstate: 2015-07-07 18:07:00`,
				`========================================================`,
				``,
				`...`,
				`5 active connections`,
				`Connection Number: 0`,
				`	Operating Mode: NORMAL`,
				`	 com.google.android.gms.fitness.sensors.d.b | WakeLockRefCount 0 | uid 10013 | cache size 0 | max cache size 0`,
				`	 BMI160 Step counter 0x00000018 | status: active | pending flush events 0 `,
				`Connection Number: 1 `,
				`	Operating Mode: NORMAL`,
				`	 com.google.android.location.collectionlib.w | WakeLockRefCount 0 | uid 10013 | cache size 0 | max cache size 0`,
				`	 BMP280 pressure 0x00000004 | status: active | pending flush events 0 `,
				`Connection Number: 2 `,
				`	Operating Mode: NORMAL`,
				`	 com.android.server.display.AutomaticBrightnessController | WakeLockRefCount 0 | uid 1000 | cache size 0 | max cache size 0`,
				`	 RPR0521 light 0x00000007 | status: active | pending flush events 0 `,
				`Connection Number: 3 `,
				`	Operating Mode: NORMAL`,
				`	 com.android.server.policy.WindowOrientationListener | WakeLockRefCount 0 | uid 1000 | cache size 0 | max cache size 0`,
				`	 Window Orientation 0x0000001f | status: active | pending flush events 0 `,
				`Connection Number: 4 `,
				`	Operating Mode: NORMAL`,
				`	 civ | WakeLockRefCount 0 | uid 10182 | cache size 0 | max cache size 0`,
				`	 BMI160 accelerometer 0x00000001 | status: active | pending flush events 0 `,
				`Previous Registrations:`,
			}, "\n"),
			wantActiveConn: []*acpb.ActiveConn{
				{
					Number:        1,
					OperatingMode: "NORMAL",
					PackageName:   "com.google.android.gms.fitness.sensors.d.b",
					UID:           10013,
					SensorNumber:  24,
					PendingFlush:  0,
				},
				{
					Number:        2,
					OperatingMode: "NORMAL",
					PackageName:   "com.google.android.location.collectionlib.w",
					UID:           10013,
					SensorNumber:  4,
					PendingFlush:  0,
				},
				{
					Number:        3,
					OperatingMode: "NORMAL",
					PackageName:   "com.android.server.display.AutomaticBrightnessController",
					UID:           1000,
					SensorNumber:  7,
					PendingFlush:  0,
				},
				{
					Number:        4,
					OperatingMode: "NORMAL",
					PackageName:   "com.android.server.policy.WindowOrientationListener",
					UID:           1000,
					SensorNumber:  31,
					PendingFlush:  0,
				},
				{
					Number:        5,
					OperatingMode: "NORMAL",
					PackageName:   "civ",
					UID:           10182,
					SensorNumber:  1,
					PendingFlush:  0,
				},
			},
		},
		{
			name: "Parse (missing information for one connection)",
			finput: strings.Join([]string{
				`========================================================`,
				`== dumpstate: 2015-07-07 18:07:00`,
				`========================================================`,
				``,
				`...`,
				`5 active connections`,
				`Connection Number: 0`,
				`	Operating Mode: NORMAL`,
				`	 com.google.android.gms.fitness.sensors.d.b | WakeLockRefCount 0 | uid 10013 | cache size 0 | max cache size 0`,
				`	 BMI160 Step counter 0x00000018 | status: active | pending flush events 0 `,
				`Connection Number: 1 `,
				`	Operating Mode: NORMAL`,
				`	 BMP280 pressure 0x00000004 | status: active | pending flush events 0 `,
				`Previous Registrations:`,
			}, "\n"),
			wantActiveConn: []*acpb.ActiveConn{
				{
					Number:        1,
					OperatingMode: "NORMAL",
					PackageName:   "com.google.android.gms.fitness.sensors.d.b",
					UID:           10013,
					SensorNumber:  24,
					PendingFlush:  0,
				},
				{
					Number:        2,
					OperatingMode: "NORMAL",
					PackageName:   "",
					UID:           -1,
					SensorNumber:  4,
					PendingFlush:  0,
				},
			},
		},
		{
			name: "Parse (repeated information for active connection)",
			finput: strings.Join([]string{
				`========================================================`,
				`== dumpstate: 2015-07-07 18:07:00`,
				`========================================================`,
				``,
				`...`,
				`5 active connections`,
				`Connection Number: 0`,
				`	Operating Mode: NORMAL`,
				`	 com.google.android.gms.fitness.sensors.d.b | WakeLockRefCount 0 | uid 10013 | cache size 0 | max cache size 0`,
				`	 BMI160 Step counter 0x00000018 | status: active | pending flush events 0 `,
				`Connection Number: 1 `,
				`	Operating Mode: NORMAL`,
				`	 com.google.android.location.collectionlib.w | WakeLockRefCount 0 | uid 10013 | cache size 0 | max cache size 0`,
				`	 com.android.server.display.AutomaticBrightnessController | WakeLockRefCount 0 | uid 1000 | cache size 0 | max cache size 0`,
				`	 RPR0521 light 0x00000007 | status: active | pending flush events 0 `,
				`	 Window Orientation 0x0000001f | status: active | pending flush events 0 `,
			}, "\n"),
			wantActiveConn: []*acpb.ActiveConn{
				{
					Number:        1,
					OperatingMode: "NORMAL",
					PackageName:   "com.google.android.gms.fitness.sensors.d.b",
					UID:           10013,
					SensorNumber:  24,
					PendingFlush:  0,
				},
				{
					Number:        2,
					OperatingMode: "NORMAL",
					PackageName:   "com.android.server.display.AutomaticBrightnessController",
					UID:           1000,
					SensorNumber:  31,
					PendingFlush:  0,
				},
			},
		},
	}
	for _, test := range tests {
		OutputData := Parse(test.finput, meta)
		if OutputData.Errs != nil {
			t.Errorf("%v: error: %q", test.name, OutputData.Errs)
		}
		if !reflect.DeepEqual(OutputData.ActiveConns, test.wantActiveConn) {
			t.Errorf("%v:\n  got : %v\n  want: %v", test.name, OutputData.ActiveConns, test.wantActiveConn)
		}
	}
}
