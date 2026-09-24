package binding

import (
	"encoding"
	"errors"
	"fmt"
	"maps"
	"mime/multipart"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/king54346/gin-tiny/internal/bytesconv"
	"github.com/king54346/gin-tiny/internal/json"
)

var (
	errUnknownType = errors.New("unknown type")

	// ErrConvertMapStringSlice can not convert to map[string][]string
	ErrConvertMapStringSlice = errors.New("can not convert to map slices of strings")

	// ErrConvertToMapString can not convert to map[string]string
	ErrConvertToMapString = errors.New("can not convert to map of strings")
)

func mapURI(ptr any, m map[string][]string) error {
	return mapFormByTag(ptr, m, "uri")
}

func mapForm(ptr any, form map[string][]string) error {
	return mapFormByTag(ptr, form, "form")
}

func MapFormWithTag(ptr any, form map[string][]string, tag string) error {
	return mapFormByTag(ptr, form, tag)
}

var emptyField = reflect.StructField{}

func mapFormByTag(ptr any, form map[string][]string, tag string) error {
	// Check if ptr is a map
	ptrVal := reflect.ValueOf(ptr)
	var pointed any
	if ptrVal.Kind() == reflect.Pointer {
		ptrVal = ptrVal.Elem()
		pointed = ptrVal.Interface()
	}
	if ptrVal.Kind() == reflect.Map &&
		ptrVal.Type().Key().Kind() == reflect.String {
		if pointed != nil {
			ptr = pointed
		}
		return setFormMap(ptr, form)
	}

	return mappingByPtr(ptr, formSource(form), tag)
}

// setter tries to set value on a walking by fields of a struct
type setter interface {
	TrySet(value reflect.Value, field reflect.StructField, key string, opt setOptions) (isSet bool, err error)
}

type formSource map[string][]string

var _ setter = formSource(nil)

// TrySet tries to set a value by request's form source (like map[string][]string)
func (form formSource) TrySet(value reflect.Value, field reflect.StructField, tagValue string, opt setOptions) (isSet bool, err error) {
	return setByForm(value, field, form, tagValue, opt)
}

func mappingByPtr(ptr any, setter setter, tag string) error {
	_, err := mapping(reflect.ValueOf(ptr), emptyField, setter, tag)
	return err
}

func mapping(value reflect.Value, field reflect.StructField, setter setter, tag string) (bool, error) {
	return mappingRec(value, field, setter, tag, nil)
}

// mappingRec 是 mapping 的递归实现。creating 记录当前递归链上「为 nil 指针新建值」的类型：
// 自引用结构体（如 type Node struct{ Next *Node }）每层都会新建一个值再递归进去，
// 不加限制会无限递归直到栈溢出（fatal error，recover 无法拦截，整个进程退出）。
// 表单键是扁平的，同一类型在同一条链上第二次新建只会重复映射同样的键，没有意义，直接停止
func mappingRec(value reflect.Value, field reflect.StructField, setter setter, tag string, creating []reflect.Type) (bool, error) {
	if field.Tag.Get(tag) == "-" { // just ignoring this field
		return false, nil
	}

	vKind := value.Kind()

	if vKind == reflect.Pointer {
		var isNew bool
		vPtr := value
		if value.IsNil() {
			elem := value.Type().Elem()
			if slices.Contains(creating, elem) {
				return false, nil
			}
			creating = append(creating[:len(creating):len(creating)], elem)
			isNew = true
			vPtr = reflect.New(elem)
		}
		isSet, err := mappingRec(vPtr.Elem(), field, setter, tag, creating)
		if err != nil {
			return false, err
		}
		if isNew && isSet {
			value.Set(vPtr)
		}
		return isSet, nil
	}

	if vKind != reflect.Struct || !field.Anonymous {
		ok, err := tryToSetValue(value, field, setter, tag)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}

	if vKind == reflect.Struct {
		tValue := value.Type()

		var isSet bool
		for i := range value.NumField() {
			sf := tValue.Field(i)
			if sf.PkgPath != "" && !sf.Anonymous { // unexported
				continue
			}
			ok, err := mappingRec(value.Field(i), sf, setter, tag, creating)
			if err != nil {
				return false, err
			}
			isSet = isSet || ok
		}
		return isSet, nil
	}
	return false, nil
}

type setOptions struct {
	isDefaultExists bool
	defaultValue    string
	// parser 指定优先使用的解析接口，目前只支持 "encoding.TextUnmarshaler"
	parser string
}

func tryToSetValue(value reflect.Value, field reflect.StructField, setter setter, tag string) (bool, error) {
	var tagValue string
	var setOpt setOptions

	tagValue = field.Tag.Get(tag)
	tagValue, opts, _ := strings.Cut(tagValue, ",")

	if tagValue == "" { // default value is FieldName
		tagValue = field.Name
	}
	if tagValue == "" { // when field is "emptyField" variable
		return false, nil
	}

	var opt string
	for len(opts) > 0 {
		opt, opts, _ = strings.Cut(opts, ",")

		k, v, _ := strings.Cut(opt, "=")
		switch k {
		case "default":
			setOpt.isDefaultExists = true
			setOpt.defaultValue = v
		case "parser":
			setOpt.parser = v
		}
	}

	return setter.TrySet(value, field, tagValue, setOpt)
}

func setByForm(value reflect.Value, field reflect.StructField, form map[string][]string, tagValue string, opt setOptions) (isSet bool, err error) {
	vs, ok := form[tagValue]
	if !ok && !opt.isDefaultExists {
		return false, nil
	}

	switch value.Kind() {
	case reflect.Slice, reflect.Array:
		// 键存在但没有值时与键不存在同样处理：有默认值用默认值，否则不绑定
		if len(vs) == 0 {
			if !opt.isDefaultExists {
				return false, nil
			}
			vs = defaultValues(field, opt.defaultValue)
		}

		// 类型自身实现了自定义解析接口时作为整体解析（如把 "a/b/c" 解析成自定义切片类型），
		// 不再按切片规则逐个元素绑定
		if set, err := trySetCustom(vs[0], value, opt.parser); set {
			return true, err
		}

		if vs, err = trySplit(vs, field); err != nil {
			return false, err
		}

		if value.Kind() == reflect.Slice {
			return true, setSlice(vs, value, field, opt)
		}
		if len(vs) != value.Len() {
			return false, fmt.Errorf("%q is not valid value for %s", vs, value.Type().String())
		}
		return true, setArray(vs, value, field, opt)
	default:
		// 键不存在、没有值或值为空字符串时都使用默认值
		val := opt.defaultValue
		if len(vs) > 0 && vs[0] != "" {
			val = vs[0]
		}
		return true, setWithProperType(val, value, field, opt)
	}
}

// defaultValues 把切片/数组字段的默认值拆成多个值。标签里逗号用来分隔选项，
// 所以多个默认值用分号分隔，如 `form:",default=1;2;3"`
func defaultValues(field reflect.StructField, def string) []string {
	switch field.Tag.Get("collection_format") {
	case "", "multi":
		return strings.Split(def, ";")
	case "csv":
		// 转成逗号分隔后交给 trySplit 按 csv 规则拆分
		return []string{strings.ReplaceAll(def, ";", ",")}
	default:
		return []string{def}
	}
}

// trySplit 按 collection_format 标签把每个值拆成多个元素，multi（默认）表示每个值就是一个元素
func trySplit(vs []string, field reflect.StructField) ([]string, error) {
	var sep string
	switch cf := field.Tag.Get("collection_format"); cf {
	case "", "multi":
		return vs, nil
	case "csv":
		sep = ","
	case "ssv":
		sep = " "
	case "tsv":
		sep = "\t"
	case "pipes":
		sep = "|"
	default:
		return nil, fmt.Errorf("%s is not supported in the collection_format. (multi, csv, ssv, tsv, pipes)", cf)
	}

	n := 0
	for _, v := range vs {
		n += strings.Count(v, sep) + 1
	}
	newVs := make([]string, 0, n)
	for _, v := range vs {
		newVs = append(newVs, strings.Split(v, sep)...)
	}
	return newVs, nil
}

// BindUnmarshaler 由需要自定义解析规则的类型实现，适用于表单、查询参数、路径参数和请求头绑定。
// 例如让 ?date=2024-01-02 直接绑定到自定义日期类型，或把 "a,b,c" 解析成自定义集合类型
type BindUnmarshaler interface {
	// UnmarshalParam 解析单个参数值并赋给接收者
	UnmarshalParam(param string) error
}

// trySetCustom 字段类型（的指针）实现了自定义解析接口时交给它解析，优先于内置的类型转换规则。
// 标签指定 parser=encoding.TextUnmarshaler 且类型实现了该接口时优先用 UnmarshalText；
// 否则使用 BindUnmarshaler。未指定 parser 时即使实现了 TextUnmarshaler 也不使用，保持向后兼容
func trySetCustom(val string, value reflect.Value, parser string) (isSet bool, err error) {
	if !value.CanAddr() {
		return false, nil
	}
	ptr := value.Addr().Interface()
	if parser == "encoding.TextUnmarshaler" {
		if u, ok := ptr.(encoding.TextUnmarshaler); ok {
			return true, u.UnmarshalText(bytesconv.StringToBytes(val))
		}
	}
	if u, ok := ptr.(BindUnmarshaler); ok {
		return true, u.UnmarshalParam(val)
	}
	return false, nil
}

func setWithProperType(val string, value reflect.Value, field reflect.StructField, opt setOptions) error {
	if ok, err := trySetCustom(val, value, opt.parser); ok {
		return err
	}
	switch value.Kind() {
	case reflect.Int:
		return setIntField(val, 0, value)
	case reflect.Int8:
		return setIntField(val, 8, value)
	case reflect.Int16:
		return setIntField(val, 16, value)
	case reflect.Int32:
		return setIntField(val, 32, value)
	case reflect.Int64:
		switch value.Interface().(type) {
		case time.Duration:
			return setTimeDuration(val, value)
		}
		return setIntField(val, 64, value)
	case reflect.Uint:
		return setUintField(val, 0, value)
	case reflect.Uint8:
		return setUintField(val, 8, value)
	case reflect.Uint16:
		return setUintField(val, 16, value)
	case reflect.Uint32:
		return setUintField(val, 32, value)
	case reflect.Uint64:
		return setUintField(val, 64, value)
	case reflect.Bool:
		return setBoolField(val, value)
	case reflect.Float32:
		return setFloatField(val, 32, value)
	case reflect.Float64:
		return setFloatField(val, 64, value)
	case reflect.String:
		value.SetString(val)
	case reflect.Struct:
		switch value.Interface().(type) {
		case time.Time:
			return setTimeField(val, field, value)
		case multipart.FileHeader:
			// 文件只能来自 multipart 请求的文件部分，普通表单值不做解析
			return nil
		}
		return json.Unmarshal(bytesconv.StringToBytes(val), value.Addr().Interface())
	case reflect.Map:
		return json.Unmarshal(bytesconv.StringToBytes(val), value.Addr().Interface())
	case reflect.Pointer:
		// 切片/数组元素为指针时（如 []*T）逐个分配后按元素类型解析
		if value.IsNil() {
			value.Set(reflect.New(value.Type().Elem()))
		}
		return setWithProperType(val, value.Elem(), field, opt)
	default:
		return errUnknownType
	}
	return nil
}

func setIntField(val string, bitSize int, field reflect.Value) error {
	if val == "" {
		val = "0"
	}
	intVal, err := strconv.ParseInt(val, 10, bitSize)
	if err == nil {
		field.SetInt(intVal)
	}
	return err
}

func setUintField(val string, bitSize int, field reflect.Value) error {
	if val == "" {
		val = "0"
	}
	uintVal, err := strconv.ParseUint(val, 10, bitSize)
	if err == nil {
		field.SetUint(uintVal)
	}
	return err
}

func setBoolField(val string, field reflect.Value) error {
	if val == "" {
		val = "false"
	}
	boolVal, err := strconv.ParseBool(val)
	if err == nil {
		field.SetBool(boolVal)
	}
	return err
}

func setFloatField(val string, bitSize int, field reflect.Value) error {
	if val == "" {
		val = "0.0"
	}
	floatVal, err := strconv.ParseFloat(val, bitSize)
	if err == nil {
		field.SetFloat(floatVal)
	}
	return err
}

func setTimeField(val string, structField reflect.StructField, value reflect.Value) error {
	timeFormat := structField.Tag.Get("time_format")
	if timeFormat == "" {
		timeFormat = time.RFC3339
	}

	// 空值或全是空白时视为未传，设为零值
	if val = strings.TrimSpace(val); val == "" {
		value.Set(reflect.ValueOf(time.Time{}))
		return nil
	}

	switch tf := strings.ToLower(timeFormat); tf {
	case "unix", "unixmilli", "unixmicro", "unixnano":
		tv, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return err
		}

		var t time.Time
		switch tf {
		case "unix":
			t = time.Unix(tv, 0)
		case "unixmilli":
			t = time.UnixMilli(tv)
		case "unixmicro":
			t = time.UnixMicro(tv)
		default:
			t = time.Unix(0, tv)
		}
		if isUTC, _ := strconv.ParseBool(structField.Tag.Get("time_utc")); isUTC {
			t = t.UTC()
		}

		value.Set(reflect.ValueOf(t))
		return nil
	}

	l := time.Local
	if isUTC, _ := strconv.ParseBool(structField.Tag.Get("time_utc")); isUTC {
		l = time.UTC
	}

	if locTag := structField.Tag.Get("time_location"); locTag != "" {
		loc, err := time.LoadLocation(locTag)
		if err != nil {
			return err
		}
		l = loc
	}

	t, err := time.ParseInLocation(timeFormat, val, l)
	if err != nil {
		return err
	}

	value.Set(reflect.ValueOf(t))
	return nil
}

func setArray(vals []string, value reflect.Value, field reflect.StructField, opt setOptions) error {
	for i, s := range vals {
		err := setWithProperType(s, value.Index(i), field, opt)
		if err != nil {
			return err
		}
	}
	return nil
}

func setSlice(vals []string, value reflect.Value, field reflect.StructField, opt setOptions) error {
	slice := reflect.MakeSlice(value.Type(), len(vals), len(vals))
	err := setArray(vals, slice, field, opt)
	if err != nil {
		return err
	}
	value.Set(slice)
	return nil
}

func setTimeDuration(val string, value reflect.Value) error {
	// 空值或全是空白时视为未传，设为零值
	if val = strings.TrimSpace(val); val == "" {
		value.SetInt(0)
		return nil
	}
	d, err := time.ParseDuration(val)
	if err != nil {
		return err
	}
	value.Set(reflect.ValueOf(d))
	return nil
}

func setFormMap(ptr any, form map[string][]string) error {
	el := reflect.TypeOf(ptr).Elem()

	if el.Kind() == reflect.Slice {
		ptrMap, ok := ptr.(map[string][]string)
		if !ok {
			return ErrConvertMapStringSlice
		}
		maps.Copy(ptrMap, form)
		return nil
	}

	ptrMap, ok := ptr.(map[string]string)
	if !ok {
		return ErrConvertToMapString
	}
	for k, v := range form {
		// 手工构造的 url.Values 可能出现空切片，取最后一个值前要判断
		if len(v) > 0 {
			ptrMap[k] = v[len(v)-1] // pick last
		}
	}

	return nil
}
