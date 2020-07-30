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

// Protocol buffers for storing active connection information.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.24.0-devel
// 	protoc        v3.12.3
// source: github.com/googleinterns/sensor-historian/pb/sensorsinfo_proto/sensorsinfo.proto

package sensorsinfo

import (
	proto "github.com/golang/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type RequestMode int32

const (
	RequestMode_CONTINUOUS RequestMode = 0
	RequestMode_ON_CHANGE  RequestMode = 1
	RequestMode_ONE_SHOT   RequestMode = 2
	RequestMode_SPECIAL    RequestMode = 3
)

// Enum value maps for RequestMode.
var (
	RequestMode_name = map[int32]string{
		0: "CONTINUOUS",
		1: "ON_CHANGE",
		2: "ONE_SHOT",
		3: "SPECIAL",
	}
	RequestMode_value = map[string]int32{
		"CONTINUOUS": 0,
		"ON_CHANGE":  1,
		"ONE_SHOT":   2,
		"SPECIAL":    3,
	}
)

func (x RequestMode) Enum() *RequestMode {
	p := new(RequestMode)
	*p = x
	return p
}

func (x RequestMode) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (RequestMode) Descriptor() protoreflect.EnumDescriptor {
	return file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_enumTypes[0].Descriptor()
}

func (RequestMode) Type() protoreflect.EnumType {
	return &file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_enumTypes[0]
}

func (x RequestMode) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use RequestMode.Descriptor instead.
func (RequestMode) EnumDescriptor() ([]byte, []int) {
	return file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_rawDescGZIP(), []int{0}
}

// DirectConn contains information about a direct connection.
type DirectConn struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Number                 int32  `protobuf:"varint,1,opt,name=Number,proto3" json:"Number,omitempty"`
	PackageName            string `protobuf:"bytes,2,opt,name=PackageName,proto3" json:"PackageName,omitempty"`
	HALChannelHandle       int32  `protobuf:"varint,3,opt,name=HALChannelHandle,proto3" json:"HALChannelHandle,omitempty"`
	SensorNumber           int32  `protobuf:"varint,4,opt,name=SensorNumber,proto3" json:"SensorNumber,omitempty"`
	RateLevel              int32  `protobuf:"varint,5,opt,name=RateLevel,proto3" json:"RateLevel,omitempty"`
	HasSensorserviceRecord bool   `protobuf:"varint,6,opt,name=HasSensorserviceRecord,proto3" json:"HasSensorserviceRecord,omitempty"`
	Source                 string `protobuf:"bytes,7,opt,name=Source,proto3" json:"Source,omitempty"`
}

func (x *DirectConn) Reset() {
	*x = DirectConn{}
	if protoimpl.UnsafeEnabled {
		mi := &file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DirectConn) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DirectConn) ProtoMessage() {}

func (x *DirectConn) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DirectConn.ProtoReflect.Descriptor instead.
func (*DirectConn) Descriptor() ([]byte, []int) {
	return file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_rawDescGZIP(), []int{0}
}

func (x *DirectConn) GetNumber() int32 {
	if x != nil {
		return x.Number
	}
	return 0
}

func (x *DirectConn) GetPackageName() string {
	if x != nil {
		return x.PackageName
	}
	return ""
}

func (x *DirectConn) GetHALChannelHandle() int32 {
	if x != nil {
		return x.HALChannelHandle
	}
	return 0
}

func (x *DirectConn) GetSensorNumber() int32 {
	if x != nil {
		return x.SensorNumber
	}
	return 0
}

func (x *DirectConn) GetRateLevel() int32 {
	if x != nil {
		return x.RateLevel
	}
	return 0
}

func (x *DirectConn) GetHasSensorserviceRecord() bool {
	if x != nil {
		return x.HasSensorserviceRecord
	}
	return false
}

func (x *DirectConn) GetSource() string {
	if x != nil {
		return x.Source
	}
	return ""
}

// ActiveConn contains information about an active connection.
type ActiveConn struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PackageName            string  `protobuf:"bytes,1,opt,name=PackageName,proto3" json:"PackageName,omitempty"`
	UID                    int32   `protobuf:"varint,2,opt,name=UID,proto3" json:"UID,omitempty"`
	SensorNumber           int32   `protobuf:"varint,3,opt,name=SensorNumber,proto3" json:"SensorNumber,omitempty"`
	Number                 int32   `protobuf:"varint,4,opt,name=Number,proto3" json:"Number,omitempty"`
	PendingFlush           int32   `protobuf:"varint,5,opt,name=PendingFlush,proto3" json:"PendingFlush,omitempty"`
	SamplingRateHz         float64 `protobuf:"fixed64,6,opt,name=SamplingRateHz,proto3" json:"SamplingRateHz,omitempty"`
	BatchingPeriodS        float64 `protobuf:"fixed64,7,opt,name=BatchingPeriodS,proto3" json:"BatchingPeriodS,omitempty"`
	HasSensorserviceRecord bool    `protobuf:"varint,8,opt,name=HasSensorserviceRecord,proto3" json:"HasSensorserviceRecord,omitempty"`
	OperatingMode          string  `protobuf:"bytes,9,opt,name=OperatingMode,proto3" json:"OperatingMode,omitempty"`
	Source                 string  `protobuf:"bytes,10,opt,name=Source,proto3" json:"Source,omitempty"`
}

func (x *ActiveConn) Reset() {
	*x = ActiveConn{}
	if protoimpl.UnsafeEnabled {
		mi := &file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ActiveConn) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ActiveConn) ProtoMessage() {}

func (x *ActiveConn) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ActiveConn.ProtoReflect.Descriptor instead.
func (*ActiveConn) Descriptor() ([]byte, []int) {
	return file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_rawDescGZIP(), []int{1}
}

func (x *ActiveConn) GetPackageName() string {
	if x != nil {
		return x.PackageName
	}
	return ""
}

func (x *ActiveConn) GetUID() int32 {
	if x != nil {
		return x.UID
	}
	return 0
}

func (x *ActiveConn) GetSensorNumber() int32 {
	if x != nil {
		return x.SensorNumber
	}
	return 0
}

func (x *ActiveConn) GetNumber() int32 {
	if x != nil {
		return x.Number
	}
	return 0
}

func (x *ActiveConn) GetPendingFlush() int32 {
	if x != nil {
		return x.PendingFlush
	}
	return 0
}

func (x *ActiveConn) GetSamplingRateHz() float64 {
	if x != nil {
		return x.SamplingRateHz
	}
	return 0
}

func (x *ActiveConn) GetBatchingPeriodS() float64 {
	if x != nil {
		return x.BatchingPeriodS
	}
	return 0
}

func (x *ActiveConn) GetHasSensorserviceRecord() bool {
	if x != nil {
		return x.HasSensorserviceRecord
	}
	return false
}

func (x *ActiveConn) GetOperatingMode() string {
	if x != nil {
		return x.OperatingMode
	}
	return ""
}

func (x *ActiveConn) GetSource() string {
	if x != nil {
		return x.Source
	}
	return ""
}

// SubscriptionInfo contains information about one subscription event of
// a sensor to an application.
type SubscriptionInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	StartMs         int64   `protobuf:"varint,1,opt,name=StartMs,proto3" json:"StartMs,omitempty"`
	EndMs           int64   `protobuf:"varint,2,opt,name=EndMs,proto3" json:"EndMs,omitempty"`
	SensorNumber    int32   `protobuf:"varint,3,opt,name=SensorNumber,proto3" json:"SensorNumber,omitempty"`
	UID             int32   `protobuf:"varint,4,opt,name=UID,proto3" json:"UID,omitempty"`
	PackageName     string  `protobuf:"bytes,5,opt,name=PackageName,proto3" json:"PackageName,omitempty"`
	SamplingRateHz  float64 `protobuf:"fixed64,6,opt,name=SamplingRateHz,proto3" json:"SamplingRateHz,omitempty"`
	BatchingPeriodS float64 `protobuf:"fixed64,7,opt,name=BatchingPeriodS,proto3" json:"BatchingPeriodS,omitempty"`
	Source          string  `protobuf:"bytes,8,opt,name=Source,proto3" json:"Source,omitempty"`
}

func (x *SubscriptionInfo) Reset() {
	*x = SubscriptionInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SubscriptionInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SubscriptionInfo) ProtoMessage() {}

func (x *SubscriptionInfo) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SubscriptionInfo.ProtoReflect.Descriptor instead.
func (*SubscriptionInfo) Descriptor() ([]byte, []int) {
	return file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_rawDescGZIP(), []int{2}
}

func (x *SubscriptionInfo) GetStartMs() int64 {
	if x != nil {
		return x.StartMs
	}
	return 0
}

func (x *SubscriptionInfo) GetEndMs() int64 {
	if x != nil {
		return x.EndMs
	}
	return 0
}

func (x *SubscriptionInfo) GetSensorNumber() int32 {
	if x != nil {
		return x.SensorNumber
	}
	return 0
}

func (x *SubscriptionInfo) GetUID() int32 {
	if x != nil {
		return x.UID
	}
	return 0
}

func (x *SubscriptionInfo) GetPackageName() string {
	if x != nil {
		return x.PackageName
	}
	return ""
}

func (x *SubscriptionInfo) GetSamplingRateHz() float64 {
	if x != nil {
		return x.SamplingRateHz
	}
	return 0
}

func (x *SubscriptionInfo) GetBatchingPeriodS() float64 {
	if x != nil {
		return x.BatchingPeriodS
	}
	return 0
}

func (x *SubscriptionInfo) GetSource() string {
	if x != nil {
		return x.Source
	}
	return ""
}

type Sensor struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Number      int32       `protobuf:"varint,1,opt,name=Number,proto3" json:"Number,omitempty"`
	Name        string      `protobuf:"bytes,2,opt,name=Name,proto3" json:"Name,omitempty"`
	Type        string      `protobuf:"bytes,3,opt,name=Type,proto3" json:"Type,omitempty"`
	RequestMode RequestMode `protobuf:"varint,4,opt,name=RequestMode,proto3,enum=sensorsinfo.RequestMode" json:"RequestMode,omitempty"`
	MaxRateHz   float64     `protobuf:"fixed64,5,opt,name=MaxRateHz,proto3" json:"MaxRateHz,omitempty"`
	MinRateHz   float64     `protobuf:"fixed64,6,opt,name=MinRateHz,proto3" json:"MinRateHz,omitempty"`
	Version     int32       `protobuf:"varint,7,opt,name=Version,proto3" json:"Version,omitempty"`
	Max         int32       `protobuf:"varint,8,opt,name=Max,proto3" json:"Max,omitempty"`
	Reserved    int32       `protobuf:"varint,9,opt,name=Reserved,proto3" json:"Reserved,omitempty"`
	Batch       bool        `protobuf:"varint,10,opt,name=Batch,proto3" json:"Batch,omitempty"`
	WakeUp      bool        `protobuf:"varint,11,opt,name=WakeUp,proto3" json:"WakeUp,omitempty"`
}

func (x *Sensor) Reset() {
	*x = Sensor{}
	if protoimpl.UnsafeEnabled {
		mi := &file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Sensor) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Sensor) ProtoMessage() {}

func (x *Sensor) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Sensor.ProtoReflect.Descriptor instead.
func (*Sensor) Descriptor() ([]byte, []int) {
	return file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_rawDescGZIP(), []int{3}
}

func (x *Sensor) GetNumber() int32 {
	if x != nil {
		return x.Number
	}
	return 0
}

func (x *Sensor) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Sensor) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *Sensor) GetRequestMode() RequestMode {
	if x != nil {
		return x.RequestMode
	}
	return RequestMode_CONTINUOUS
}

func (x *Sensor) GetMaxRateHz() float64 {
	if x != nil {
		return x.MaxRateHz
	}
	return 0
}

func (x *Sensor) GetMinRateHz() float64 {
	if x != nil {
		return x.MinRateHz
	}
	return 0
}

func (x *Sensor) GetVersion() int32 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *Sensor) GetMax() int32 {
	if x != nil {
		return x.Max
	}
	return 0
}

func (x *Sensor) GetReserved() int32 {
	if x != nil {
		return x.Reserved
	}
	return 0
}

func (x *Sensor) GetBatch() bool {
	if x != nil {
		return x.Batch
	}
	return false
}

func (x *Sensor) GetWakeUp() bool {
	if x != nil {
		return x.WakeUp
	}
	return false
}

type App struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	UID              int32    `protobuf:"varint,1,opt,name=UID,proto3" json:"UID,omitempty"`
	PackageName      string   `protobuf:"bytes,2,opt,name=PackageName,proto3" json:"PackageName,omitempty"`
	SensorActivities []string `protobuf:"bytes,3,rep,name=SensorActivities,proto3" json:"SensorActivities,omitempty"`
}

func (x *App) Reset() {
	*x = App{}
	if protoimpl.UnsafeEnabled {
		mi := &file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *App) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*App) ProtoMessage() {}

func (x *App) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use App.ProtoReflect.Descriptor instead.
func (*App) Descriptor() ([]byte, []int) {
	return file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_rawDescGZIP(), []int{4}
}

func (x *App) GetUID() int32 {
	if x != nil {
		return x.UID
	}
	return 0
}

func (x *App) GetPackageName() string {
	if x != nil {
		return x.PackageName
	}
	return ""
}

func (x *App) GetSensorActivities() []string {
	if x != nil {
		return x.SensorActivities
	}
	return nil
}

type AllSensorsInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AllActiveConns []*ActiveConn `protobuf:"bytes,1,rep,name=AllActiveConns,proto3" json:"AllActiveConns,omitempty"`
	AllDirectConns []*DirectConn `protobuf:"bytes,2,rep,name=AllDirectConns,proto3" json:"AllDirectConns,omitempty"`
	Sensors        []*Sensor     `protobuf:"bytes,3,rep,name=Sensors,proto3" json:"Sensors,omitempty"`
	Apps           []*App        `protobuf:"bytes,4,rep,name=Apps,proto3" json:"Apps,omitempty"`
}

func (x *AllSensorsInfo) Reset() {
	*x = AllSensorsInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AllSensorsInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AllSensorsInfo) ProtoMessage() {}

func (x *AllSensorsInfo) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AllSensorsInfo.ProtoReflect.Descriptor instead.
func (*AllSensorsInfo) Descriptor() ([]byte, []int) {
	return file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_rawDescGZIP(), []int{5}
}

func (x *AllSensorsInfo) GetAllActiveConns() []*ActiveConn {
	if x != nil {
		return x.AllActiveConns
	}
	return nil
}

func (x *AllSensorsInfo) GetAllDirectConns() []*DirectConn {
	if x != nil {
		return x.AllDirectConns
	}
	return nil
}

func (x *AllSensorsInfo) GetSensors() []*Sensor {
	if x != nil {
		return x.Sensors
	}
	return nil
}

func (x *AllSensorsInfo) GetApps() []*App {
	if x != nil {
		return x.Apps
	}
	return nil
}

var File_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto protoreflect.FileDescriptor

var file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_rawDesc = []byte{
	0x0a, 0x50, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x73, 0x2f, 0x73, 0x65, 0x6e, 0x73, 0x6f,
	0x72, 0x2d, 0x68, 0x69, 0x73, 0x74, 0x6f, 0x72, 0x69, 0x61, 0x6e, 0x2f, 0x70, 0x62, 0x2f, 0x73,
	0x65, 0x6e, 0x73, 0x6f, 0x72, 0x73, 0x69, 0x6e, 0x66, 0x6f, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x2f, 0x73, 0x65, 0x6e, 0x73, 0x6f, 0x72, 0x73, 0x69, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x12, 0x0b, 0x73, 0x65, 0x6e, 0x73, 0x6f, 0x72, 0x73, 0x69, 0x6e, 0x66, 0x6f, 0x22,
	0x84, 0x02, 0x0a, 0x0a, 0x44, 0x69, 0x72, 0x65, 0x63, 0x74, 0x43, 0x6f, 0x6e, 0x6e, 0x12, 0x16,
	0x0a, 0x06, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x52, 0x06,
	0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x12, 0x20, 0x0a, 0x0b, 0x50, 0x61, 0x63, 0x6b, 0x61, 0x67,
	0x65, 0x4e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x50, 0x61, 0x63,
	0x6b, 0x61, 0x67, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x2a, 0x0a, 0x10, 0x48, 0x41, 0x4c, 0x43,
	0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x48, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x05, 0x52, 0x10, 0x48, 0x41, 0x4c, 0x43, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x48, 0x61,
	0x6e, 0x64, 0x6c, 0x65, 0x12, 0x22, 0x0a, 0x0c, 0x53, 0x65, 0x6e, 0x73, 0x6f, 0x72, 0x4e, 0x75,
	0x6d, 0x62, 0x65, 0x72, 0x18, 0x04, 0x20, 0x01, 0x28, 0x05, 0x52, 0x0c, 0x53, 0x65, 0x6e, 0x73,
	0x6f, 0x72, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x12, 0x1c, 0x0a, 0x09, 0x52, 0x61, 0x74, 0x65,
	0x4c, 0x65, 0x76, 0x65, 0x6c, 0x18, 0x05, 0x20, 0x01, 0x28, 0x05, 0x52, 0x09, 0x52, 0x61, 0x74,
	0x65, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x12, 0x36, 0x0a, 0x16, 0x48, 0x61, 0x73, 0x53, 0x65, 0x6e,
	0x73, 0x6f, 0x72, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64,
	0x18, 0x06, 0x20, 0x01, 0x28, 0x08, 0x52, 0x16, 0x48, 0x61, 0x73, 0x53, 0x65, 0x6e, 0x73, 0x6f,
	0x72, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x12, 0x16,
	0x0a, 0x06, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06,
	0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x22, 0xe8, 0x02, 0x0a, 0x0a, 0x41, 0x63, 0x74, 0x69, 0x76,
	0x65, 0x43, 0x6f, 0x6e, 0x6e, 0x12, 0x20, 0x0a, 0x0b, 0x50, 0x61, 0x63, 0x6b, 0x61, 0x67, 0x65,
	0x4e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x50, 0x61, 0x63, 0x6b,
	0x61, 0x67, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x55, 0x49, 0x44, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x05, 0x52, 0x03, 0x55, 0x49, 0x44, 0x12, 0x22, 0x0a, 0x0c, 0x53, 0x65, 0x6e,
	0x73, 0x6f, 0x72, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x05, 0x52,
	0x0c, 0x53, 0x65, 0x6e, 0x73, 0x6f, 0x72, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x12, 0x16, 0x0a,
	0x06, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x18, 0x04, 0x20, 0x01, 0x28, 0x05, 0x52, 0x06, 0x4e,
	0x75, 0x6d, 0x62, 0x65, 0x72, 0x12, 0x22, 0x0a, 0x0c, 0x50, 0x65, 0x6e, 0x64, 0x69, 0x6e, 0x67,
	0x46, 0x6c, 0x75, 0x73, 0x68, 0x18, 0x05, 0x20, 0x01, 0x28, 0x05, 0x52, 0x0c, 0x50, 0x65, 0x6e,
	0x64, 0x69, 0x6e, 0x67, 0x46, 0x6c, 0x75, 0x73, 0x68, 0x12, 0x26, 0x0a, 0x0e, 0x53, 0x61, 0x6d,
	0x70, 0x6c, 0x69, 0x6e, 0x67, 0x52, 0x61, 0x74, 0x65, 0x48, 0x7a, 0x18, 0x06, 0x20, 0x01, 0x28,
	0x01, 0x52, 0x0e, 0x53, 0x61, 0x6d, 0x70, 0x6c, 0x69, 0x6e, 0x67, 0x52, 0x61, 0x74, 0x65, 0x48,
	0x7a, 0x12, 0x28, 0x0a, 0x0f, 0x42, 0x61, 0x74, 0x63, 0x68, 0x69, 0x6e, 0x67, 0x50, 0x65, 0x72,
	0x69, 0x6f, 0x64, 0x53, 0x18, 0x07, 0x20, 0x01, 0x28, 0x01, 0x52, 0x0f, 0x42, 0x61, 0x74, 0x63,
	0x68, 0x69, 0x6e, 0x67, 0x50, 0x65, 0x72, 0x69, 0x6f, 0x64, 0x53, 0x12, 0x36, 0x0a, 0x16, 0x48,
	0x61, 0x73, 0x53, 0x65, 0x6e, 0x73, 0x6f, 0x72, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x52,
	0x65, 0x63, 0x6f, 0x72, 0x64, 0x18, 0x08, 0x20, 0x01, 0x28, 0x08, 0x52, 0x16, 0x48, 0x61, 0x73,
	0x53, 0x65, 0x6e, 0x73, 0x6f, 0x72, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x52, 0x65, 0x63,
	0x6f, 0x72, 0x64, 0x12, 0x24, 0x0a, 0x0d, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6e, 0x67,
	0x4d, 0x6f, 0x64, 0x65, 0x18, 0x09, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x4f, 0x70, 0x65, 0x72,
	0x61, 0x74, 0x69, 0x6e, 0x67, 0x4d, 0x6f, 0x64, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x53, 0x6f, 0x75,
	0x72, 0x63, 0x65, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x53, 0x6f, 0x75, 0x72, 0x63,
	0x65, 0x22, 0x84, 0x02, 0x0a, 0x10, 0x53, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69,
	0x6f, 0x6e, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x18, 0x0a, 0x07, 0x53, 0x74, 0x61, 0x72, 0x74, 0x4d,
	0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x07, 0x53, 0x74, 0x61, 0x72, 0x74, 0x4d, 0x73,
	0x12, 0x14, 0x0a, 0x05, 0x45, 0x6e, 0x64, 0x4d, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x03, 0x52,
	0x05, 0x45, 0x6e, 0x64, 0x4d, 0x73, 0x12, 0x22, 0x0a, 0x0c, 0x53, 0x65, 0x6e, 0x73, 0x6f, 0x72,
	0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x05, 0x52, 0x0c, 0x53, 0x65,
	0x6e, 0x73, 0x6f, 0x72, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x12, 0x10, 0x0a, 0x03, 0x55, 0x49,
	0x44, 0x18, 0x04, 0x20, 0x01, 0x28, 0x05, 0x52, 0x03, 0x55, 0x49, 0x44, 0x12, 0x20, 0x0a, 0x0b,
	0x50, 0x61, 0x63, 0x6b, 0x61, 0x67, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x0b, 0x50, 0x61, 0x63, 0x6b, 0x61, 0x67, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x26,
	0x0a, 0x0e, 0x53, 0x61, 0x6d, 0x70, 0x6c, 0x69, 0x6e, 0x67, 0x52, 0x61, 0x74, 0x65, 0x48, 0x7a,
	0x18, 0x06, 0x20, 0x01, 0x28, 0x01, 0x52, 0x0e, 0x53, 0x61, 0x6d, 0x70, 0x6c, 0x69, 0x6e, 0x67,
	0x52, 0x61, 0x74, 0x65, 0x48, 0x7a, 0x12, 0x28, 0x0a, 0x0f, 0x42, 0x61, 0x74, 0x63, 0x68, 0x69,
	0x6e, 0x67, 0x50, 0x65, 0x72, 0x69, 0x6f, 0x64, 0x53, 0x18, 0x07, 0x20, 0x01, 0x28, 0x01, 0x52,
	0x0f, 0x42, 0x61, 0x74, 0x63, 0x68, 0x69, 0x6e, 0x67, 0x50, 0x65, 0x72, 0x69, 0x6f, 0x64, 0x53,
	0x12, 0x16, 0x0a, 0x06, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x18, 0x08, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x06, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x22, 0xb6, 0x02, 0x0a, 0x06, 0x53, 0x65, 0x6e,
	0x73, 0x6f, 0x72, 0x12, 0x16, 0x0a, 0x06, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x05, 0x52, 0x06, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x12, 0x12, 0x0a, 0x04, 0x4e,
	0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x4e, 0x61, 0x6d, 0x65, 0x12,
	0x12, 0x0a, 0x04, 0x54, 0x79, 0x70, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x54,
	0x79, 0x70, 0x65, 0x12, 0x3a, 0x0a, 0x0b, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x4d, 0x6f,
	0x64, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x18, 0x2e, 0x73, 0x65, 0x6e, 0x73, 0x6f,
	0x72, 0x73, 0x69, 0x6e, 0x66, 0x6f, 0x2e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x4d, 0x6f,
	0x64, 0x65, 0x52, 0x0b, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x4d, 0x6f, 0x64, 0x65, 0x12,
	0x1c, 0x0a, 0x09, 0x4d, 0x61, 0x78, 0x52, 0x61, 0x74, 0x65, 0x48, 0x7a, 0x18, 0x05, 0x20, 0x01,
	0x28, 0x01, 0x52, 0x09, 0x4d, 0x61, 0x78, 0x52, 0x61, 0x74, 0x65, 0x48, 0x7a, 0x12, 0x1c, 0x0a,
	0x09, 0x4d, 0x69, 0x6e, 0x52, 0x61, 0x74, 0x65, 0x48, 0x7a, 0x18, 0x06, 0x20, 0x01, 0x28, 0x01,
	0x52, 0x09, 0x4d, 0x69, 0x6e, 0x52, 0x61, 0x74, 0x65, 0x48, 0x7a, 0x12, 0x18, 0x0a, 0x07, 0x56,
	0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x07, 0x20, 0x01, 0x28, 0x05, 0x52, 0x07, 0x56, 0x65,
	0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x10, 0x0a, 0x03, 0x4d, 0x61, 0x78, 0x18, 0x08, 0x20, 0x01,
	0x28, 0x05, 0x52, 0x03, 0x4d, 0x61, 0x78, 0x12, 0x1a, 0x0a, 0x08, 0x52, 0x65, 0x73, 0x65, 0x72,
	0x76, 0x65, 0x64, 0x18, 0x09, 0x20, 0x01, 0x28, 0x05, 0x52, 0x08, 0x52, 0x65, 0x73, 0x65, 0x72,
	0x76, 0x65, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x42, 0x61, 0x74, 0x63, 0x68, 0x18, 0x0a, 0x20, 0x01,
	0x28, 0x08, 0x52, 0x05, 0x42, 0x61, 0x74, 0x63, 0x68, 0x12, 0x16, 0x0a, 0x06, 0x57, 0x61, 0x6b,
	0x65, 0x55, 0x70, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x08, 0x52, 0x06, 0x57, 0x61, 0x6b, 0x65, 0x55,
	0x70, 0x22, 0x65, 0x0a, 0x03, 0x41, 0x70, 0x70, 0x12, 0x10, 0x0a, 0x03, 0x55, 0x49, 0x44, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x05, 0x52, 0x03, 0x55, 0x49, 0x44, 0x12, 0x20, 0x0a, 0x0b, 0x50, 0x61,
	0x63, 0x6b, 0x61, 0x67, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x0b, 0x50, 0x61, 0x63, 0x6b, 0x61, 0x67, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x2a, 0x0a, 0x10,
	0x53, 0x65, 0x6e, 0x73, 0x6f, 0x72, 0x41, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x69, 0x65, 0x73,
	0x18, 0x03, 0x20, 0x03, 0x28, 0x09, 0x52, 0x10, 0x53, 0x65, 0x6e, 0x73, 0x6f, 0x72, 0x41, 0x63,
	0x74, 0x69, 0x76, 0x69, 0x74, 0x69, 0x65, 0x73, 0x22, 0xe7, 0x01, 0x0a, 0x0e, 0x41, 0x6c, 0x6c,
	0x53, 0x65, 0x6e, 0x73, 0x6f, 0x72, 0x73, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x3f, 0x0a, 0x0e, 0x41,
	0x6c, 0x6c, 0x41, 0x63, 0x74, 0x69, 0x76, 0x65, 0x43, 0x6f, 0x6e, 0x6e, 0x73, 0x18, 0x01, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x73, 0x65, 0x6e, 0x73, 0x6f, 0x72, 0x73, 0x69, 0x6e, 0x66,
	0x6f, 0x2e, 0x41, 0x63, 0x74, 0x69, 0x76, 0x65, 0x43, 0x6f, 0x6e, 0x6e, 0x52, 0x0e, 0x41, 0x6c,
	0x6c, 0x41, 0x63, 0x74, 0x69, 0x76, 0x65, 0x43, 0x6f, 0x6e, 0x6e, 0x73, 0x12, 0x3f, 0x0a, 0x0e,
	0x41, 0x6c, 0x6c, 0x44, 0x69, 0x72, 0x65, 0x63, 0x74, 0x43, 0x6f, 0x6e, 0x6e, 0x73, 0x18, 0x02,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x73, 0x65, 0x6e, 0x73, 0x6f, 0x72, 0x73, 0x69, 0x6e,
	0x66, 0x6f, 0x2e, 0x44, 0x69, 0x72, 0x65, 0x63, 0x74, 0x43, 0x6f, 0x6e, 0x6e, 0x52, 0x0e, 0x41,
	0x6c, 0x6c, 0x44, 0x69, 0x72, 0x65, 0x63, 0x74, 0x43, 0x6f, 0x6e, 0x6e, 0x73, 0x12, 0x2d, 0x0a,
	0x07, 0x53, 0x65, 0x6e, 0x73, 0x6f, 0x72, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x13,
	0x2e, 0x73, 0x65, 0x6e, 0x73, 0x6f, 0x72, 0x73, 0x69, 0x6e, 0x66, 0x6f, 0x2e, 0x53, 0x65, 0x6e,
	0x73, 0x6f, 0x72, 0x52, 0x07, 0x53, 0x65, 0x6e, 0x73, 0x6f, 0x72, 0x73, 0x12, 0x24, 0x0a, 0x04,
	0x41, 0x70, 0x70, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x73, 0x65, 0x6e,
	0x73, 0x6f, 0x72, 0x73, 0x69, 0x6e, 0x66, 0x6f, 0x2e, 0x41, 0x70, 0x70, 0x52, 0x04, 0x41, 0x70,
	0x70, 0x73, 0x2a, 0x47, 0x0a, 0x0b, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x4d, 0x6f, 0x64,
	0x65, 0x12, 0x0e, 0x0a, 0x0a, 0x43, 0x4f, 0x4e, 0x54, 0x49, 0x4e, 0x55, 0x4f, 0x55, 0x53, 0x10,
	0x00, 0x12, 0x0d, 0x0a, 0x09, 0x4f, 0x4e, 0x5f, 0x43, 0x48, 0x41, 0x4e, 0x47, 0x45, 0x10, 0x01,
	0x12, 0x0c, 0x0a, 0x08, 0x4f, 0x4e, 0x45, 0x5f, 0x53, 0x48, 0x4f, 0x54, 0x10, 0x02, 0x12, 0x0b,
	0x0a, 0x07, 0x53, 0x50, 0x45, 0x43, 0x49, 0x41, 0x4c, 0x10, 0x03, 0x42, 0x4c, 0x5a, 0x4a, 0x67,
	0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x73, 0x2f, 0x73, 0x65, 0x6e, 0x73, 0x6f, 0x72, 0x2d, 0x68,
	0x69, 0x73, 0x74, 0x6f, 0x72, 0x69, 0x61, 0x6e, 0x2f, 0x70, 0x62, 0x2f, 0x73, 0x65, 0x6e, 0x73,
	0x6f, 0x72, 0x73, 0x69, 0x6e, 0x66, 0x6f, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x3b, 0x73, 0x65,
	0x6e, 0x73, 0x6f, 0x72, 0x73, 0x69, 0x6e, 0x66, 0x6f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_rawDescOnce sync.Once
	file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_rawDescData = file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_rawDesc
)

func file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_rawDescGZIP() []byte {
	file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_rawDescOnce.Do(func() {
		file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_rawDescData = protoimpl.X.CompressGZIP(file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_rawDescData)
	})
	return file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_rawDescData
}

var file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_goTypes = []interface{}{
	(RequestMode)(0),         // 0: sensorsinfo.RequestMode
	(*DirectConn)(nil),       // 1: sensorsinfo.DirectConn
	(*ActiveConn)(nil),       // 2: sensorsinfo.ActiveConn
	(*SubscriptionInfo)(nil), // 3: sensorsinfo.SubscriptionInfo
	(*Sensor)(nil),           // 4: sensorsinfo.Sensor
	(*App)(nil),              // 5: sensorsinfo.App
	(*AllSensorsInfo)(nil),   // 6: sensorsinfo.AllSensorsInfo
}
var file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_depIdxs = []int32{
	0, // 0: sensorsinfo.Sensor.RequestMode:type_name -> sensorsinfo.RequestMode
	2, // 1: sensorsinfo.AllSensorsInfo.AllActiveConns:type_name -> sensorsinfo.ActiveConn
	1, // 2: sensorsinfo.AllSensorsInfo.AllDirectConns:type_name -> sensorsinfo.DirectConn
	4, // 3: sensorsinfo.AllSensorsInfo.Sensors:type_name -> sensorsinfo.Sensor
	5, // 4: sensorsinfo.AllSensorsInfo.Apps:type_name -> sensorsinfo.App
	5, // [5:5] is the sub-list for method output_type
	5, // [5:5] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() {
	file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_init()
}
func file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_init() {
	if File_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DirectConn); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ActiveConn); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SubscriptionInfo); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Sensor); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*App); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AllSensorsInfo); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_goTypes,
		DependencyIndexes: file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_depIdxs,
		EnumInfos:         file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_enumTypes,
		MessageInfos:      file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_msgTypes,
	}.Build()
	File_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto = out.File
	file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_rawDesc = nil
	file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_goTypes = nil
	file_github_com_googleinterns_sensor_historian_pb_sensorsinfo_proto_sensorsinfo_proto_depIdxs = nil
}
