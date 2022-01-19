package grpc_opa_middleware

import (
	"reflect"
	"testing"
)

func Test_IsNilInterface(t *testing.T) {
	for idx, tst := range nilInterfaceTests {
		actual := IsNilInterface(tst.value)
		//actual = !actual  // this is for debugging the test cases
		if actual != tst.expected {
			t.Errorf(`tst#%d: FAIL: name=%s\nvalue=%#v\nexpected=%v\nactual=%v`,
				idx, tst.name, tst.value, tst.expected, actual)
			if tst.value != nil {
				t.Errorf(`tst#%d: FAIL: kind=%s`,
					idx, reflect.TypeOf(tst.value).Kind())
			}
		}
	}
}

var uninitializedStringVar string

type myStructType struct{}
var uninitializedStructVar myStructType

type myPtrType *myStructType
var uninitializedPtrVar myPtrType

type myMapType map[string]string
var uninitializedMapVar myMapType

type myArrayType [3]string
var uninitializedArrayVar myArrayType

type mySliceType []string
var uninitializedSliceVar mySliceType

type myFuncType func(*testing.T)
var uninitializedFuncVar myFuncType
func myTestFunc(*testing.T){}
var initializedFuncVar myFuncType = myTestFunc

type myChanType chan string
var uninitializedChanVar myChanType

type myInterfaceType interface{ myMethod() }
func (myST *myStructType) myMethod() {}
var uninitializedStructPtrVar *myStructType
var uninitializedInterfaceVar myInterfaceType
var nilinitializedInterfaceVar myInterfaceType = uninitializedStructPtrVar
var valinitializedInterfaceVar myInterfaceType = &myStructType{}

var nilInterfaceTests = []struct {
	name     string
	value    interface{}
	expected bool
}{
	{
		name:     `nil value`,
		value:    nil,
		expected: true,
	},
	{
		name:     `bool value`,
		value:    false,
		expected: false,
	},
	{
		name:     `string value`,
		value:    `qwerty`,
		expected: false,
	},
	{
		name:     `int value`,
		value:    314159,
		expected: false,
	},
	{
		name:     `float value`,
		value:    3.14159,
		expected: false,
	},
	{
		name:     `uninitialized string var`,
		value:    uninitializedStringVar,
		expected: false,
	},
	{
		name:     `uninitialized Struct var`,
		value:    uninitializedStructVar,
		expected: false,
	},
	{
		name:     `initialized Struct`,
		value:    myStructType{},
		expected: false,
	},
	{
		name:     `uninitialized Ptr var`,
		value:    uninitializedPtrVar,
		expected: true,
	},
	{
		name:     `initialized Ptr`,
		value:    &myStructType{},
		expected: false,
	},
	{
		name:     `uninitialized Map var`,
		value:    uninitializedMapVar,
		expected: true,
	},
	{
		name:     `initialized Map`,
		value:    myMapType{},
		expected: false,
	},
	{
		name:     `uninitialized Array var`,
		value:    uninitializedArrayVar,
		expected: false,
	},
	{
		name:     `initialized Array`,
		value:    myArrayType{},
		expected: false,
	},
	{
		name:     `uninitialized Slice var`,
		value:    uninitializedSliceVar,
		expected: true,
	},
	{
		name:     `initialized Slice`,
		value:    mySliceType{},
		expected: false,
	},
	{
		name:     `uninitialized Func var`,
		value:    uninitializedFuncVar,
		expected: true,
	},
	{
		name:     `initialized Func`,
		value:    initializedFuncVar,
		expected: false,
	},
	{
		name:     `uninitialized Chan var`,
		value:    uninitializedChanVar,
		expected: true,
	},
	{
		name:     `initialized Chan`,
		value:    make(myChanType),
		expected: false,
	},
	{
		name:     `uninitialized Interface var`,
		value:    uninitializedInterfaceVar,
		expected: true,
	},
	{
		name:     `nil initialized Interface`,
		value:    nilinitializedInterfaceVar,
		expected: true,
	},
	{
		name:     `val initialized Interface`,
		value:    valinitializedInterfaceVar,
		expected: false,
	},
}
