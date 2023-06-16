package utils

import "reflect"

// IsNilInterface returns whether the interface parameter is nil
// Ref: https://mangatmodi.medium.com/go-check-nil-interface-the-right-way-d142776edef1
func IsNilInterface(i interface{}) bool {
	if i == nil {
		return true
	}

	switch reflect.TypeOf(i).Kind() {
	case reflect.Interface, reflect.Func, reflect.Ptr, reflect.Map, reflect.Chan, reflect.Slice:
		return reflect.ValueOf(i).IsNil()
	}

	return false
}
