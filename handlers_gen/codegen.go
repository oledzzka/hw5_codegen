package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"text/template"
	"unicode"
)

const (
	validatorPrefix = "apivalidator:"
	spacePrefix     = " "
	commentPrefix   = "//"
	commaString     = ","
	enumSeparator   = "|"
	stringType      = "string"
	intType         = "int"
	pkgContext      = "context"
	objContext      = "Context"
	get             = "GET"
	post            = "POST"
	equal           = "="
	apiGenApiPrefix = "apigen:api "
	requiredString  = "required"
	paramnameString = "paramname"
	enumString      = "enum"
	defaultString   = "default"
	minString       = "min"
	maxString       = "max"
)

var (
	supportedTypes = []string{stringType, intType}
	supportMethods = []string{get, post}
	hasAuthStruct  = []string{}
	structPathMap  = map[string][]methodPath{}
)

type methodPath struct {
	Path       string
	MethodName string
}

type apiGenSettings struct {
	// "url": "/user/create", "auth": true, "method": "POST"
	URL    string `json:"url"`
	Auth   bool
	Method string
}

type templMethodArguments struct {
	ApiGenSettings  *apiGenSettings
	StructName      string
	MethodName      string
	ParamStructName string
}

type templStructGetterArguments struct {
	StructName string
	Fields     []string
}

type validatorGenSettings struct {
	StructName string
	Type       string
	FieldName  string
	Required   bool
	ParamName  string
	Enum       []string
	IsDefault  bool
	Default    string
	Max        string
	Min        string
}

const commonCode = `
import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
)

const (
	mustNotBeEmptyPostfix = " must me not empty"
	shouldBeInteger       = " must be int"
	lenStringMustBeGrateThan = " len must be >= "
	minIntError = " must be >= %%d"
	maxIntError = " must be <= %%d"
	enumError = " must be one of [%%s]"
)

func handleError(w http.ResponseWriter, err error) {
	var apiError *ApiError
	if errors.As(err, apiError) {
		w.WriteHeader(apiError.HTTPStatus)
	}
	w.Write([]byte(err.Error()))
}

func getRequestParams(r *http.Request) (map[string][]string, error) {
	res := make(map[string][]string)
	query := r.URL.Query()
	for k, v := range query {
		res[k] = v
	}
	if r.Body == nil {
		return res, nil
	}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	bodymap, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, err
	}
	for k, v := range bodymap {
		res[k] = v
	}
	return res, nil
}

func hasStringInSlice(value string, enum []string) bool {
	for _, v := range enum {
		if v == value {
			return true
		}
	}
	return false
}
`

var (
	wrapperFuncTmpl = template.Must(template.New("wrapperFuncTmpl").Parse(`
// wrapper for {{.MethodName}}
func (srv *{{.StructName}}) wrapper{{.MethodName}}(w http.ResponseWriter, r *http.Request) { {{ if .ApiGenSettings.Auth }} 
	// check authorization
	if err := srv.authorizeRequest(r); err != nil {
		handleError(w, err)
		return 
	}{{ end }}
	// check http method
	if r.Method != "{{.ApiGenSettings.Method}}" {
		handleError(w, &ApiError{
			HTTPStatus: 400,
			Err:        errors.New("bad method"),
		})
		return
	}
	paramsMap, err := getRequestParams(r)
	if err != nil {
		handleError(w, err)
		return
	}
	inPoint, err := get{{.ParamStructName}}FromParams(paramsMap)
	if err != nil {
		handleError(w, err)
		return
	}
	out, err := srv.{{.MethodName}}(r.Context(), *inPoint)
	if err != nil {
		handleError(w, err)
		return
	}
	body, err := json.Marshal(out)
	if err != nil {
		handleError(w, err)
		return
	}
	w.Write(body)
}
`))

	authMethodTmpl = template.Must(template.New("authMethodTmpl").Parse(`
// authorizeRequest check authorization
func (srv *{{.StructName}}) authorizeRequest(r *http.Request) error {
	if r.Header.Get("X-Auth") != "100500" {
		return &ApiError{
			HTTPStatus: 401,
			Err: errors.New("unauthorized"),
		}
	}
	return nil
}
`))

	stringValidationTemplate = template.Must(
		template.New("stringValidationTemplate").Parse(`
{{ $length := len .Enum}}{{ if ne $length 0 }}
// Enum for {{.FieldName}} of {{.StructName}} structure
var enum{{.StructName}}{{.FieldName}} = []string{ {{range .Enum}}"{{.}}",{{end}} }
{{end}}

// Getter {{.FieldName}} of {{.StructName}} structure
func get{{.StructName}}{{.FieldName}}(params map[string][]string) (string,error) {
	values := params["{{.ParamName}}"]
	var value string
	if len(values) > 0 {
		value = values[0]
	}{{ if .IsDefault }}
	if value == "" {
		value = "{{ .Default }}"
	}{{ end }}{{ if .Required }}
	if value == "" {
		return "", &ApiError{
			HTTPStatus: 400,
			Err:        errors.New("{{.FieldName}}" + mustNotBeEmptyPostfix),
		}
	}{{ end }}{{ $length := len .Enum}}{{ if ne $length 0 }}
	if !hasStringInSlice(value, enum{{.StructName}}{{.FieldName}}) {
		return "", &ApiError{
			HTTPStatus: 400,
			Err:        errors.New("{{.FieldName}}" + mustNotBeEmptyPostfix),
		}
	}{{ end }}{{ if .Min }}
	if len(value) < {{ .Min }} {
		return "", &ApiError{
			HTTPStatus: 400,
			Err:        errors.New("{{.FieldName}}" + lenStringMustBeGrateThan + "{{ .Min }}"),
		}
	}{{ end }}
	return value, nil
}`))

	numberValidationTemplate = template.Must(template.New("numberValidationTemplate").Parse(`
// Getter {{.FieldName}} of {{.StructName}} structure
func get{{.StructName}}{{.FieldName}}(params map[string][]string) (int,error) {
	values := params["{{.ParamName}}"]
	var value string
	if len(values) > 0 {
		value = values[0]
	}
	var (
		num int
		err error
	)
	if value != "" {
		num, err = strconv.Atoi(value)
		if err != nil {
			return 0, &ApiError{
				HTTPStatus: 400,
				Err:        errors.New("{{.FieldName}}" + shouldBeInteger),
			}
		}
	}{{ if .IsDefault }}
	if num == 0 {
		num = {{.Default}}
	}{{ end }}{{ if .Required }}
	if required && num == 0 {
		return 0, &ApiError{
			HTTPStatus: 400,
			Err:        errors.New("{{.FieldName}}" + mustNotBeEmptyPostfix),
		}
	}{{ end }}{{ if ne .Min  "" }}
	if num < {{ .Min }} {
		return 0, &ApiError{
			HTTPStatus: 400,
			Err:        errors.New("{{.FieldName}}" + mustNotBeEmptyPostfix),
		}
	}{{ end }}{{ if ne .Max "" }}
	if max != nil && num > *max {
		return 0, &ApiError{
			HTTPStatus: 400,
			Err:        errors.New("{{.FieldName}}" + mustNotBeEmptyPostfix),
		}
	}{{ end }}
	return num, nil
}
`))

	structGetterFromParamsTemplate = template.Must(template.New("numberValidationTemplate").Parse(`
// Getter {{.StructName}} from params
func get{{.StructName}}FromParams(params map[string][]string)(*{{.StructName}}, error){
	s := new({{.StructName}}){{ $structName := .StructName }}
	var err error{{ range .Fields }}
	s.{{.}}, err = get{{$structName}}{{.}}(params)
	if err != nil {
		return nil, err
	}{{ end }}
	return s, err
}
`))
	structServeMethodParamsTemplate = template.Must(template.New("numberValidationTemplate").Parse(`
// Serve http {{.StructName}}
func (srv *{{.StructName}} ) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path { {{range .Paths}}
	case "{{.Path}}":
		srv.wrapper{{.MethodName}}(w, r){{end}}
	default:
		handleError(w, &ApiError{
			HTTPStatus: 404,
			Err:        errors.New("path not exists"),
		})
	}
}
`))
)

func main() {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, os.Args[1], nil, parser.ParseComments)
	if err != nil {
		log.Fatal(err)
	}

	out, err := os.Create(os.Args[2])
	if err != nil {
		log.Fatal(err)
	}

	fmt.Fprintln(out, `package `+node.Name.Name)
	fmt.Fprintln(out) // empty line
	fmt.Fprintln(out, commonCode)

	// struct validation generate
	for _, d := range node.Decls {
		switch d.(type) {
		case *ast.GenDecl:
			gen, ok := d.(*ast.GenDecl)
			if !ok {
				continue
			}
			if gen.Tok != token.TYPE {
				continue
			}
			for _, spec := range gen.Specs {
				typeSpec, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				structSpec, ok := typeSpec.Type.(*ast.StructType)
				if !ok {
					continue
				}
				handleStruct(out, typeSpec.Name.Name, structSpec)
			}
		}
	}
	for _, d := range node.Decls {
		switch d.(type) {
		case *ast.FuncDecl:
			g := d.(*ast.FuncDecl)
			generateMethod(out, g)
		}
	}
	for str, paths := range structPathMap {
		if len(paths) == 0 {
			continue
		}
		structServeMethodParamsTemplate.Execute(out, map[string]interface{}{
			"StructName": str,
			"Paths":      paths,
		})
	}
}

func handleStruct(out io.Writer, structName string, structSpec *ast.StructType) {
	if !checkHaveStructValidator(structSpec) {
		return
	}
	generateStructureValidator(out, structName, structSpec)
}

func checkHaveStructValidator(structSpec *ast.StructType) bool {
	for _, f := range structSpec.Fields.List {
		if f.Tag == nil {
			continue
		}
		tagText := strings.TrimLeft(strings.TrimLeft(f.Tag.Value, commentPrefix), spacePrefix)
		tagText = strings.TrimLeft(tagText, "`")
		if strings.HasPrefix(tagText, validatorPrefix) {
			return true
		}
	}
	return false
}

func generateStructureValidator(out io.Writer, structName string, structSpec *ast.StructType) {
	var fieldNames []string
	for _, field := range structSpec.Fields.List {
		i, ok := field.Type.(*ast.Ident)
		if !ok {
			log.Fatal(fmt.Sprintf("error during generate code for structure %s", structName))
		}
		fieldName := field.Names[0].Name
		fieldType := i.Name
		validationSettings := parseGenerateValidationString(structName, fieldName, fieldType, field.Tag.Value)
		fieldNames = append(fieldNames, fieldName)
		switch fieldType {
		case "string":
			stringValidationTemplate.Execute(out, validationSettings)
		case "int":
			numberValidationTemplate.Execute(out, validationSettings)
		default:
			log.Fatal(
				fmt.Sprintf("error field type %q for field %q in structure %s", fieldType, fieldName, structName),
			)
		}
	}
	structGetterFromParamsTemplate.Execute(out, templStructGetterArguments{
		StructName: structName,
		Fields:     fieldNames,
	})
}

func parseGenerateValidationString(structName, fieldName, fieldType, comment string) *validatorGenSettings {
	settings := &validatorGenSettings{
		FieldName:  fieldName,
		Type:       fieldType,
		StructName: structName,
		ParamName:  lowercaseFirstLetter(fieldName),
	}
	comment = getApiCommentFromString(comment)
	if comment == "" {
		return settings
	}
	for _, c := range strings.Split(comment, commaString) {
		cSplit := strings.SplitN(c, equal, 2)
		k := cSplit[0]
		var v string
		if len(cSplit) == 2 {
			v = cSplit[1]
		}
		switch k {
		case requiredString:
			settings.Required = true
		case defaultString:
			settings.IsDefault = true
			settings.Default = v
		case paramnameString:
			settings.ParamName = v
		case enumString:
			settings.Enum = strings.Split(v, enumSeparator)
		case minString:
			_, err := strconv.Atoi(v)
			if err != nil {
				log.Fatal(fmt.Sprintf("field %s has bad value for argument min %s", fieldName, v))
			}
			settings.Min = v
		case maxString:
			_, err := strconv.Atoi(v)
			if err != nil {
				log.Fatal(fmt.Sprintf("field %s has bad value for argument max %s", fieldName, v))
			}
			settings.Min = v
		default:
			log.Fatal(fmt.Sprintf("field %s has bad argument %s", fieldName, k))
		}
	}
	return settings
}

func getApiCommentFromString(comment string) string {
	comment = strings.Trim(comment, "`")
	comments := strings.Split(comment, spacePrefix)
	for _, c := range comments {
		if strings.HasPrefix(c, validatorPrefix) {
			c = strings.TrimLeft(c, validatorPrefix)
			return c[1 : len(c)-1]
		}
	}
	return ""
}

func getReceiverName(mf *ast.FuncDecl) string {
	if mf.Recv != nil {
		for _, v := range mf.Recv.List {
			switch xv := v.Type.(type) {
			case *ast.StarExpr:
				if si, ok := xv.X.(*ast.Ident); ok {
					return si.Name
				}
			case *ast.Ident:
				return xv.Name
			}
		}
	}
	return ""
}

func generateMethod(out *os.File, g *ast.FuncDecl) {
	decl := findDeclaration(g)
	if decl == nil {
		return
	}
	if g.Recv == nil {
		log.Fatal(fmt.Sprintf("apigen for simple function %q", g.Name.Name))
	}
	if len(g.Type.Params.List) != 2 {
		log.Fatal(fmt.Sprintf("bad method %q signature", g.Name.Name))
	}
	paramName := g.Type.Params.List[1].Type.(*ast.Ident).Name
	structName := getReceiverName(g)
	wrapperFuncTmpl.Execute(out, templMethodArguments{
		StructName:      structName,
		ParamStructName: paramName,
		MethodName:      g.Name.Name,
		ApiGenSettings:  decl,
	})
	if len(g.Type.Params.List) != 2 {
		log.Fatal(fmt.Sprintf("method %s should have two params", g.Name.Name))
	}
	params := g.Type.Params.List

	in, ok := params[0].Type.(*ast.SelectorExpr)
	if !ok {
		log.Fatal(fmt.Sprintf("the first parameter of method %s should be context", g.Name.Name))
	}
	id, ok := in.X.(*ast.Ident)
	if !ok {
		log.Fatal(fmt.Sprintf("the second parameter of method %s should be context", g.Name.Name))
	}
	if id.Name != pkgContext || in.Sel.Name != "Context" {
		log.Fatal(fmt.Sprintf("method %s should have the first parameter context", g.Name.Name))
	}
	if decl.Auth && !hasStringInSlice(structName, hasAuthStruct) {
		hasAuthStruct = append(hasAuthStruct, structName)
		authMethodTmpl.Execute(out, map[string]string{"StructName": structName})
	}
	structPathMap[structName] = append(structPathMap[structName], methodPath{
		Path:       decl.URL,
		MethodName: g.Name.Name,
	})
}

func checkMehodDeclartion(apiSettings *apiGenSettings) error {
	if apiSettings.Method == "" {
		apiSettings.Method = get
	}
	for _, m := range supportMethods {
		if apiSettings.Method == m {
			return nil
		}
	}
	return errors.New(fmt.Sprintf("not supported method %s", apiSettings.Method))
}

func findDeclaration(g *ast.FuncDecl) *apiGenSettings {
	if g.Doc == nil {
		return nil
	}
	for _, c := range g.Doc.List {
		comment := strings.TrimLeft(strings.TrimLeft(c.Text, commentPrefix), spacePrefix)
		if strings.HasPrefix(comment, apiGenApiPrefix) {
			jsonText := strings.TrimLeft(comment, apiGenApiPrefix)
			apiSettings := &apiGenSettings{}
			err := json.Unmarshal([]byte(jsonText), apiSettings)
			if err != nil {
				log.Fatal(fmt.Sprintf("Failed unmarhsal apigen json for method %q, error: %v", g.Name.Name, err))
			}
			if err := checkMehodDeclartion(apiSettings); err != nil {
				log.Fatal(fmt.Sprintf("ApiGetSetting error for method %q, error: %v", g.Name.Name, err))
			}
			return apiSettings
		}
	}
	return nil
}

func lowercaseFirstLetter(s string) string {
	copyStr := []rune(s)
	copyStr[0] = unicode.ToLower(copyStr[0])
	return string(copyStr)
}

func hasStringInSlice(s string, slice []string) bool {
	for _, ss := range slice {
		if s == ss {
			return true
		}
	}
	return false
}
